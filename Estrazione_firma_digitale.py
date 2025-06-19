import streamlit as st
import os
import zipfile
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import re
import pandas as pd
from PIL import Image
import xml.etree.ElementTree as ET
import platform
import requests

# --- Costanti per TSL -----------------------------------------------------
TSL_FILE  = Path("img/TSL-IT.xml")
TRUST_PEM = Path("trust_store.pem")

def build_trust_store(tsl_path: Path, out_pem: Path):
    ns = {
        'tsl': 'http://uri.etsi.org/02231/v2#',
        'ds':  'http://www.w3.org/2000/09/xmldsig#'
    }
    tree = ET.parse(tsl_path)
    root = tree.getroot()
    certs = root.findall('.//ds:X509Certificate', ns)
    if not certs:
        raise RuntimeError(f"Nessun certificato trovato in {tsl_path}")
    with open(out_pem, 'wb') as f:
        for cert in certs:
            b64 = cert.text.strip() if cert.text else ""
            if len(b64) < 200:
                continue
            f.write(b"-----BEGIN CERTIFICATE-----\n" + b64.encode() + b"\n-----END CERTIFICATE-----\n\n")

# Costruzione del trust store EIDAS
try:
    build_trust_store(TSL_FILE, TRUST_PEM)
except Exception as e:
    st.error(f"Impossibile costruire il trust store: {e}")
    st.stop()

# --- UI Header -------------------------------------------------------------
col1, col2 = st.columns([7,3])
with col1:
    st.title("Estrattore di file firmati (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

def extract_signed_content(p7m_path: Path, out_dir: Path) -> tuple[Path|None, str, bool]:
    base = p7m_path.stem
    payload_out = out_dir / base

    # 1) Estrai il certificato del firmatario
    cert_pem = out_dir / f"{base}_cert.pem"
    subprocess.run([
        "openssl", "pkcs7", "-inform", "DER",
        "-in", str(p7m_path), "-print_certs",
        "-out", str(cert_pem)
    ], capture_output=True)

    # 2) Tentativo 1: verify con trust_store + CApath
    verify_cmd = ["openssl", "verify", "-CAfile", str(TRUST_PEM)]
    if platform.system() in ("Linux","Darwin"):
        verify_cmd += ["-CApath", "/etc/ssl/certs"]
    verify_cmd.append(str(cert_pem))
    resv = subprocess.run(verify_cmd, capture_output=True, text=True)

    chain_pem = out_dir / f"{base}_chain.pem"
    # 3) Se fallisce, tentativo 2: estrai chain e scarica intermedio via AIA
    if resv.returncode != 0:
        # estrai tutti i cert
        subprocess.run([
            "openssl", "pkcs7", "-inform", "DER",
            "-in", str(p7m_path), "-print_certs",
            "-out", str(chain_pem)
        ], capture_output=True)
        # cerca AIA e scarica
        aia = subprocess.run([
            "openssl", "x509", "-in", str(chain_pem),
            "-noout", "-text"
        ], capture_output=True, text=True)
        for line in aia.stdout.splitlines():
            if "CA Issuers - URI:" in line:
                url = line.split("URI:")[1].strip(); break
        else:
            url = None

        if url:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code==200 and b"BEGIN CERTIFICATE" in r.content:
                    with open(chain_pem,"ab") as f: f.write(b"\n"+r.content+b"\n")
            except:
                pass

        # verifica di nuovo con intermedi
        verify_cmd2 = ["openssl","verify","-CAfile",str(TRUST_PEM),"-untrusted",str(chain_pem),str(cert_pem)]
        resv = subprocess.run(verify_cmd2, capture_output=True, text=True)

    # se ancora fallisce -> abort
    if resv.returncode != 0:
        st.error(f"Errore verifica catena «{cert_pem.name}»: {resv.stderr.strip()}")
        cert_pem.unlink(missing_ok=True)
        chain_pem.unlink(missing_ok=True)
        return None, "", False

    # 4) Estraggo il payload (fidati della catena)
    resc = subprocess.run([
        "openssl","cms","-verify",
        "-in", str(p7m_path), "-inform","DER",
        "-noverify","-out", str(payload_out)
    ], capture_output=True)
    if resc.returncode != 0:
        st.error(f"Errore estrazione «{p7m_path.name}»: {resc.stderr.decode().strip()}")
        cert_pem.unlink(missing_ok=True)
        chain_pem.unlink(missing_ok=True)
        return None, "", False

    # 5) Leggi subject e dates
    res2 = subprocess.run([
        "openssl","x509","-in", str(cert_pem),
        "-noout","-subject","-dates"
    ], capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    chain_pem.unlink(missing_ok=True)
    if res2.returncode != 0:
        st.error(f"Errore lettura info cert: {res2.stderr.strip()}")
        return payload_out, "Sconosciuto", False

    lines = res2.stdout.splitlines()
    subj = "\n".join(lines)
    signer="Sconosciuto"
    for rdn in ("CN","SN","UID","emailAddress","SERIALNUMBER"):
        m = re.search(rf"{rdn}\s*=\s*([^,/]+)", subj)
        if m: signer=m.group(1).strip(); break
    fmt="%b %d %H:%M:%S %Y %Z"
    nb=next(l for l in lines if "notBefore" in l).split("=",1)[1].strip()
    na=next(l for l in lines if "notAfter"  in l).split("=",1)[1].strip()
    valid = datetime.strptime(nb,fmt) <= datetime.utcnow() <= datetime.strptime(na,fmt)

    # 6) Rinomina se ZIP
    try:
        with open(payload_out,"rb") as f:
            if f.read(4)==b"PK\x03\x04":
                newz=payload_out.with_suffix(".zip"); payload_out.rename(newz); payload_out=newz
    except: pass

    return payload_out, signer, valid

# ZIP annidati e processing
def recursive_unpack_and_flatten(d: Path):
    for z in d.rglob("*.zip"):
        if not z.is_file(): continue
        dst = z.parent / f"{z.stem}_unz"
        shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir()
        try:
            with zipfile.ZipFile(z) as zf: zf.extractall(dst)
        except: z.unlink(missing_ok=True); continue
        z.unlink(missing_ok=True)
        children=list(dst.iterdir())
        if len(children)==1 and children[0].is_dir():
            for c in children[0].iterdir(): shutil.move(str(c), dst)
            children[0].rmdir()
        recursive_unpack_and_flatten(dst)

def process_p7m_dir(d: Path, indent=""):
    for p7m in d.rglob("*.p7m"):
        payload, signer, valid = extract_signed_content(p7m,p7m.parent)
        if not payload: continue
        p7m.unlink(missing_ok=True)
        st.write(f"{indent}– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")
        if payload.suffix.lower()==".zip":
            tmp=payload.parent
            try:
                with zipfile.ZipFile(payload) as zf:
                    inn=[n for n in zf.namelist() if n.lower().endswith(".zip")]
                    if len(inn)==1:
                        ddata=zf.read(inn[0]); tgt=tmp/Path(inn[0]).name; tgt.write_bytes(ddata)
                        with zipfile.ZipFile(tgt) as iz: iz.extractall(tmp)
                        payload.unlink(missing_ok=True)
                    else:
                        zf.extractall(tmp); payload.unlink(missing_ok=True)
            except: st.error(f"Errore estrazione ZIP interno di {payload.name}"); continue
            recursive_unpack_and_flatten(tmp)
            nested=tmp/payload.stem
            if nested.is_dir(): process_p7m_dir(nested, indent+"  ")

# Streamlit UI
output_name = st.text_input("Nome ZIP di output (.zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name+".zip"

uploads = st.file_uploader("Carica .p7m o ZIP", accept_multiple_files=True)
if uploads:
    root = Path(tempfile.mkdtemp(prefix="combined_"))
    for up in uploads:
        name, ext = up.name, Path(up.name).suffix.lower()
        tmpd = Path(tempfile.mkdtemp(prefix="proc_")); fp = tmpd/name; fp.write_bytes(up.getbuffer())

        if ext==".zip":
            st.write(f"🔄 ZIP: {name}")
            try:
                with zipfile.ZipFile(fp) as zf:
                    inn=[n for n in zf.namelist() if n.lower().endswith(".zip")]
                    if len(inn)==1:
                        data=zf.read(inn[0]); tgt=tmpd/Path(inn[0]).name; tgt.write_bytes(data)
                        with zipfile.ZipFile(tgt) as iz: iz.extractall(tmpd)
                        base=tmpd
                    else:
                        zf.extractall(tmpd); base=tmpd
            except Exception as e:
                st.error(f"Errore unzip: {e}"); shutil.rmtree(tmpd,ignore_errors=True); continue

            recursive_unpack_and_flatten(base)
            tgt=root/fp.stem; shutil.rmtree(tgt,ignore_errors=True); shutil.copytree(base,tgt)
            red=tgt/fp.stem
            if red.is_dir():
                for it in red.iterdir(): shutil.move(str(it),tgt)
                shutil.rmtree(red,ignore_errors=True)
            process_p7m_dir(tgt)
            shutil.rmtree(tmpd,ignore_errors=True)

        elif ext==".p7m":
            st.write(f"🔄 .p7m: {name}")
            payload, signer, valid = extract_signed_content(fp, root)
            if payload:
                st.write(f"– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")
            shutil.rmtree(tmpd,ignore_errors=True)

        else:
            st.warning(f"Ignoro {name}")

    # pulizia
    for d in root.rglob("*_unz"): shutil.rmtree(d,ignore_errors=True)
    for p in root.rglob("*.p7m"): p.unlink(missing_ok=True)

    # zip out
    outd=Path(tempfile.mkdtemp(prefix="zip_out_")); zipf=outd/output_filename
    with zipfile.ZipFile(zipf,'w',zipfile.ZIP_DEFLATED) as zf:
        for p in root.iterdir():
            if p.is_dir():
                for f in p.rglob("*"):
                    if f.is_file() and "_unz" not in f.parts and not f.name.lower().endswith(".p7m"):
                        zf.write(f,f.relative_to(root))
            else:
                if not p.name.lower().endswith(".p7m"): zf.write(p,p.name)

    st.subheader("Anteprima ZIP")
    with zipfile.ZipFile(zipf) as zf:
        paths=[i.filename for i in zf.infolist() if "_unz" not in i.filename and not i.filename.lower().endswith(".p7m")]
    if paths:
        rows=[p.split("/") for p in paths]; levels=max(len(r) for r in rows)
        cols=[f"Liv{i+1}" for i in range(levels)]
        df=pd.DataFrame([r+[""]*(levels-len(r)) for r in rows],columns=cols)
        for c in cols: df[c]=df[c].mask(df[c]==df[c].shift(),"")
        st.table(df)

    with open(zipf,'rb') as f:
        st.download_button("Scarica estratti",data=f,file_name=output_filename,mime="application/zip")
