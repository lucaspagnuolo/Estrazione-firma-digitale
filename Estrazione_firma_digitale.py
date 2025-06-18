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
import requests  # <— aggiunto

# --- Costanti per TSL -----------------------------------------------------
TSL_FILE  = Path("img/TSL-IT.xml")
TRUST_PEM = Path("trust_store.pem")

def build_trust_store(tsl_path: Path, out_pem: Path):
    """
    Estrae tutti i <ds:X509Certificate> dal TSL e li mette in un unico PEM.
    """
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
            pem = (
                b"-----BEGIN CERTIFICATE-----\n"
                + b64.encode('ascii')
                + b"\n-----END CERTIFICATE-----\n\n"
            )
            f.write(pem)

# Costruisco il trust store all’avvio
try:
    build_trust_store(TSL_FILE, TRUST_PEM)
except Exception as e:
    st.error(f"Impossibile costruire il trust store: {e}")
    st.stop()

# --- Header UI -------------------------------------------------------------
col1, col2 = st.columns([7,3])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# --- Estrazione contenuto e verifica firma -------------------------------
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path|None, str, bool]:
    base = p7m_file_path.stem
    output_file = output_dir / base

    # 1) Estraggo la chain di certificati (firmatario + intermedi)
    chain_pem = output_dir / f"{base}_chain.pem"
    subprocess.run([
        "openssl", "pkcs7", "-inform", "DER",
        "-in", str(p7m_file_path),
        "-print_certs",
        "-out", str(chain_pem)
    ], capture_output=True)

    # 1.1) Estrai AIA e scarica l’intermedio se mancante
    aia_proc = subprocess.run([
        "openssl", "x509", "-in", str(chain_pem),
        "-noout", "-text"
    ], capture_output=True, text=True)
    aia_url = None
    for line in aia_proc.stdout.splitlines():
        if "CA Issuers - URI:" in line:
            aia_url = line.split("URI:")[1].strip()
            break
    if aia_url:
        try:
            resp = requests.get(aia_url, timeout=5)
            if resp.status_code == 200 and b"-----BEGIN CERTIFICATE-----" in resp.content:
                with open(chain_pem, "ab") as f:
                    f.write(b"\n" + resp.content + b"\n")
            else:
                st.warning(f"Impossibile scaricare intermedio da {aia_url}")
        except Exception as e:
            st.warning(f"Errore download intermedio da {aia_url}: {e}")
    else:
        st.warning("Nessun AIA (CA Issuers) trovato: intermedi mancante")

    # 2) Verifico e estraggo il payload usando trust_store + intermedi (-certfile)
    res = subprocess.run([
        "openssl", "cms", "-verify",
        "-in", str(p7m_file_path), "-inform", "DER",
        "-CAfile", str(TRUST_PEM),
        "-certfile", str(chain_pem),
        "-out", str(output_file)
    ], capture_output=True)
    if res.returncode != 0:
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {res.stderr.decode().strip()}")
        chain_pem.unlink(missing_ok=True)
        return None, "", False

    # 3) Estraggo il certificato del firmatario per subject e dates
    cert_pem = output_dir / f"{base}_cert.pem"
    subprocess.run([
        "openssl", "pkcs7", "-inform", "DER",
        "-in", str(p7m_file_path),
        "-print_certs",
        "-out", str(cert_pem)
    ], capture_output=True)

    # 4) Leggo subject e validità
    res2 = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    chain_pem.unlink(missing_ok=True)
    if res2.returncode != 0:
        st.error(f"Errore lettura info certificato: {res2.stderr.strip()}")
        return output_file, "Sconosciuto", False

    lines = res2.stdout.splitlines()
    subj = "\n".join(lines)
    signer = "Sconosciuto"
    for rdn in ["CN","SN","UID","emailAddress","SERIALNUMBER"]:
        m = re.search(rf"{rdn}\s*=\s*([^,/]+)", subj)
        if m:
            signer = m.group(1).strip()
            break

    fmt = "%b %d %H:%M:%S %Y %Z"
    not_before = next(l for l in lines if "notBefore" in l).split("=",1)[1].strip()
    not_after  = next(l for l in lines if "notAfter" in l).split("=",1)[1].strip()
    valid = datetime.strptime(not_before, fmt) <= datetime.utcnow() <= datetime.strptime(not_after, fmt)

    # 5) Se ZIP, rinomino
    try:
        with open(output_file, "rb") as f:
            if f.read(4) == b"PK\x03\x04":
                new = output_file.with_suffix(".zip")
                output_file.rename(new)
                output_file = new
    except:
        pass

    return output_file, signer, valid

# --- Funzioni per ZIP annidati e processamento .p7m ------------------------
def recursive_unpack_and_flatten(dir: Path):
    for arc in list(dir.rglob("*.zip")):
        if not arc.is_file(): continue
        dest = arc.parent / f"{arc.stem}_unz"
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir()
        try:
            with zipfile.ZipFile(arc) as zf:
                zf.extractall(dest)
        except:
            arc.unlink(missing_ok=True)
            continue
        arc.unlink(missing_ok=True)
        items = list(dest.iterdir())
        if len(items)==1 and items[0].is_dir():
            for it in items[0].iterdir():
                shutil.move(str(it), dest)
            items[0].rmdir()
        recursive_unpack_and_flatten(dest)

def process_p7m_dir(dir: Path, indent=""):
    for p7m in dir.rglob("*.p7m"):
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        if not payload: continue
        p7m.unlink(missing_ok=True)
        st.write(f"{indent}– Estratto: **{payload.name}** | Firmato da: **{signer}** | Validità: {'✅' if valid else '⚠️'}")
        if payload.suffix.lower()==".zip":
            tmp = payload.parent
            try:
                with zipfile.ZipFile(payload) as zf:
                    inner = [n for n in zf.namelist() if n.lower().endswith(".zip")]
                    if len(inner)==1:
                        data = zf.read(inner[0])
                        tgt = tmp / Path(inner[0]).name
                        tgt.write_bytes(data)
                        with zipfile.ZipFile(tgt) as iz:
                            iz.extractall(tmp)
                        payload.unlink(missing_ok=True)
                    else:
                        zf.extractall(tmp)
                        payload.unlink(missing_ok=True)
            except Exception:
                st.error(f"Errore estrazione ZIP interno di {payload.name}")
                continue
            recursive_unpack_and_flatten(tmp)
            nested = tmp / payload.stem
            if nested.is_dir():
                process_p7m_dir(nested, indent+"  ")

# --- UI principale --------------------------------------------------------
output_name = st.text_input("Nome del file ZIP di output (.zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else f"{output_name}.zip"

uploads = st.file_uploader("Carica .p7m o ZIP contenenti .p7m", accept_multiple_files=True)
if uploads:
    root = Path(tempfile.mkdtemp(prefix="combined_"))
    for up in uploads:
        name = up.name
        ext = Path(name).suffix.lower()
        tmpd = Path(tempfile.mkdtemp(prefix="proc_"))
        fp = tmpd / name
        fp.write_bytes(up.getbuffer())

        if ext==".zip":
            st.write(f"🔄 Rilevato ZIP: {name}")
            try:
                with zipfile.ZipFile(fp) as zf:
                    inner = [n for n in zf.namelist() if n.lower().endswith(".zip")]
                    if len(inner)==1:
                        data = zf.read(inner[0])
                        tgt = tmpd / Path(inner[0]).name
                        tgt.write_bytes(data)
                        with zipfile.ZipFile(tgt) as iz:
                            iz.extractall(tmpd)
                        base_dir = tmpd
                    else:
                        zf.extractall(tmpd)
                        base_dir = tmpd
            except Exception as e:
                st.error(f"Errore estrazione ZIP: {e}")
                shutil.rmtree(tmpd, ignore_errors=True)
                continue

            recursive_unpack_and_flatten(base_dir)
            target = root / fp.stem
            shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(base_dir, target)
            red = target / fp.stem
            if red.is_dir():
                for it in red.iterdir():
                    shutil.move(str(it), target)
                shutil.rmtree(red, ignore_errors=True)

            process_p7m_dir(target)
            shutil.rmtree(tmpd, ignore_errors=True)

        elif ext==".p7m":
            st.write(f"🔄 Rilevato .p7m: {name}")
            payload, signer, valid = extract_signed_content(fp, root)
            if payload:
                st.write(f"– Estratto: **{payload.name}** | Firmato da: **{signer}** | Validità: {'✅' if valid else '⚠️'}")
            shutil.rmtree(tmpd, ignore_errors=True)

        else:
            st.warning(f"Ignoro {name}: estensione non supportata")

    # pulizia cartelle _unz e .p7m residui
    for d in root.rglob("*_unz"): shutil.rmtree(d, ignore_errors=True)
    for p in root.rglob("*.p7m"): p.unlink(missing_ok=True)

    # creo ZIP di output
    outd = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zipf = outd / output_filename
    with zipfile.ZipFile(zipf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for p in root.iterdir():
            if p.is_dir():
                for f in p.rglob("*"):
                    if f.is_file() and "_unz" not in f.parts and not f.name.lower().endswith(".p7m"):
                        zf.write(f, f.relative_to(root))
            else:
                if not p.name.lower().endswith(".p7m"):
                    zf.write(p, p.name)

    # anteprima struttura
    st.subheader("Anteprima struttura ZIP risultante")
    with zipfile.ZipFile(zipf) as zf:
        paths = [i.filename for i in zf.infolist()
                 if "_unz" not in i.filename and not i.filename.lower().endswith(".p7m")]
    if paths:
        rows = [p.split("/") for p in paths]
        levels = max(len(r) for r in rows)
        cols = [f"Liv {i+1}" for i in range(levels)]
        df = pd.DataFrame(
            [r + [""]*(levels-len(r)) for r in rows],
            columns=cols
        )
        for c in cols:
            df[c] = df[c].mask(df[c] == df[c].shift(), "")
        st.table(df)

    # download
    with open(zipf, "rb") as f:
        st.download_button(
            "Scarica ZIP estratto",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
