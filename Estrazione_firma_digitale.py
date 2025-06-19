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

# --- Costanti per TSL -----------------------------------------------------
TSL_FILE  = Path("img/TSL-IT.xml")
TRUST_PEM = Path("trust_store.pem")

def build_trust_store(tsl_path: Path, out_pem: Path):
    """
    Estrae tutti i certificati <ds:X509Certificate> dal TSL e li concatena in un unico PEM.
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
            if len(b64) < 200:  # filtro banale per saltare nodi vuoti
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

# --- Layout UI -------------------------------------------------------------
col1, col2 = st.columns([7,3])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# --- Funzione per estrarre e verificare firma -----------------------------
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path|None, str, bool]:
    base = p7m_file_path.stem
    output_file = output_dir / base

    # 1) Estrai il certificato del firmatario
    cert_pem = output_dir / f"{base}_cert.pem"
    subprocess.run([
        "openssl", "pkcs7", "-inform", "DER",
        "-in", str(p7m_file_path),
        "-print_certs",
        "-out", str(cert_pem)
    ], capture_output=True)

    # 2) Verifica la catena usando trust_store + CApath di sistema
    #    In Linux/macOS OpenSSL legge i CA intermedi da /etc/ssl/certs
    sys_ca = None
    if platform.system() in ("Linux", "Darwin"):
        sys_ca = "/etc/ssl/certs"
    verify_cmd = ["openssl", "verify", "-CAfile", str(TRUST_PEM)]
    if sys_ca:
        verify_cmd += ["-CApath", sys_ca]
    verify_cmd.append(str(cert_pem))

    resv = subprocess.run(verify_cmd, capture_output=True, text=True)
    if resv.returncode != 0:
        st.error(f"Errore verifica catena «{cert_pem.name}»: {resv.stderr.strip()}")
        cert_pem.unlink(missing_ok=True)
        return None, "", False

    # 3) Estraggo il payload senza ulteriori verifiche
    res = subprocess.run([
        "openssl", "cms", "-verify",
        "-in", str(p7m_file_path), "-inform", "DER",
        "-noverify",  # fidati: la catena è già stata validata
        "-out", str(output_file)
    ], capture_output=True)
    if res.returncode != 0:
        st.error(f"Errore estrazione payload «{p7m_file_path.name}»: {res.stderr.decode().strip()}")
        cert_pem.unlink(missing_ok=True)
        return None, "", False

    # 4) Ottengo subject e dates dal certificato
    res2 = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    if res2.returncode != 0:
        st.error(f"Errore lettura info certificato: {res2.stderr.strip()}")
        return output_file, "Sconosciuto", False

    lines = res2.stdout.splitlines()
    subj_text = "\n".join(lines)
    signer = "Sconosciuto"
    for rdn in ("CN","SN","UID","emailAddress","SERIALNUMBER"):
        m = re.search(rf"{rdn}\s*=\s*([^,/]+)", subj_text)
        if m:
            signer = m.group(1).strip()
            break

    fmt = "%b %d %H:%M:%S %Y %Z"
    not_before = next(l for l in lines if "notBefore" in l).split("=",1)[1].strip()
    not_after  = next(l for l in lines if "notAfter" in l).split("=",1)[1].strip()
    valid = datetime.strptime(not_before, fmt) <= datetime.utcnow() <= datetime.strptime(not_after, fmt)

    # 5) Se payload è ZIP, rinomina in .zip
    try:
        with open(output_file, "rb") as f:
            if f.read(4) == b"PK\x03\x04":
                new_zip = output_file.with_suffix(".zip")
                output_file.rename(new_zip)
                output_file = new_zip
    except:
        pass

    return output_file, signer, valid

# --- ZIP annidati e processamento .p7m ------------------------------------
def recursive_unpack_and_flatten(directory: Path):
    for archive in directory.rglob("*.zip"):
        if not archive.is_file(): continue
        extract_folder = archive.parent / f"{archive.stem}_unz"
        shutil.rmtree(extract_folder, ignore_errors=True)
        extract_folder.mkdir()
        try:
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(extract_folder)
        except:
            archive.unlink(missing_ok=True)
            continue
        archive.unlink(missing_ok=True)
        children = list(extract_folder.iterdir())
        if len(children) == 1 and children[0].is_dir():
            inner = children[0]
            for it in inner.iterdir():
                shutil.move(str(it), extract_folder)
            inner.rmdir()
        recursive_unpack_and_flatten(extract_folder)

def process_p7m_dir(directory: Path, indent: str = ""):
    for p7m in directory.rglob("*.p7m"):
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        if not payload:
            continue
        p7m.unlink(missing_ok=True)
        st.write(f"{indent}– Estratto: **{payload.name}** | Firmato da: **{signer}** | Validità: {'✅' if valid else '⚠️'}")
        if payload.suffix.lower() == ".zip":
            tmp = payload.parent
            try:
                with zipfile.ZipFile(payload) as zf:
                    inner_zips = [n for n in zf.namelist() if n.lower().endswith('.zip')]
                    if len(inner_zips) == 1:
                        data = zf.read(inner_zips[0])
                        target = tmp / Path(inner_zips[0]).name
                        target.write_bytes(data)
                        with zipfile.ZipFile(target) as iz:
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
                process_p7m_dir(nested, indent + "  ")

# --- Streamlit UI e flusso principale ------------------------------------
output_name = st.text_input("Nome file ZIP di output (.zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploaded_files = st.file_uploader("Carica .p7m o ZIP contenenti .p7m", accept_multiple_files=True)
if uploaded_files:
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded in uploaded_files:
        name = uploaded.name
        ext = Path(name).suffix.lower()
        tmp_dir = Path(tempfile.mkdtemp(prefix="proc_"))
        file_path = tmp_dir / name
        file_path.write_bytes(uploaded.getbuffer())

        if ext == ".zip":
            st.write(f"🔄 Rilevato ZIP: {name}")
            try:
                with zipfile.ZipFile(file_path) as zf:
                    inner = [n for n in zf.namelist() if n.lower().endswith('.zip')]
                    if len(inner) == 1:
                        data = zf.read(inner[0])
                        tgt = tmp_dir / Path(inner[0]).name
                        tgt.write_bytes(data)
                        with zipfile.ZipFile(tgt) as iz:
                            iz.extractall(tmp_dir)
                        base_dir = tmp_dir
                    else:
                        zf.extractall(tmp_dir)
                        base_dir = tmp_dir
            except Exception as e:
                st.error(f"Errore estrazione ZIP: {e}")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                continue

            recursive_unpack_and_flatten(base_dir)
            target = root_temp / file_path.stem
            shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(base_dir, target)
            redundant = target / file_path.stem
            if redundant.is_dir():
                for item in redundant.iterdir():
                    shutil.move(str(item), target)
                shutil.rmtree(redundant, ignore_errors=True)

            process_p7m_dir(target)
            shutil.rmtree(tmp_dir, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 Rilevato .p7m: {name}")
            payload, signer, valid = extract_signed_content(file_path, root_temp)
            if payload:
                st.write(f"– Estratto: **{payload.name}** | Firmato da: **{signer}** | Validità: {'✅' if valid else '⚠️'}")
            shutil.rmtree(tmp_dir, ignore_errors=True)

        else:
            st.warning(f"Ignoro {name}: estensione non supportata")

    # Pulizia residui
    for d in root_temp.rglob("*_unz"):
        shutil.rmtree(d, ignore_errors=True)
    for p in root_temp.rglob("*.p7m"):
        p.unlink(missing_ok=True)

    # Creazione ZIP di output
    out_dir = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zip_path = out_dir / output_filename
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for path in root_temp.iterdir():
            if path.is_dir():
                for file in path.rglob('*'):
                    if file.is_file() and '_unz' not in file.parts and file.suffix.lower() != '.p7m':
                        zf.write(file, file.relative_to(root_temp))
            else:
                if path.suffix.lower() != '.p7m':
                    zf.write(path, path.name)

    # Anteprima struttura ZIP risultante
    st.subheader("Anteprima struttura ZIP risultante")
    with zipfile.ZipFile(zip_path) as zf:
        paths = [i.filename for i in zf.infolist()
                 if '_unz' not in i.filename and not i.filename.lower().endswith('.p7m')]
    if paths:
        rows = [p.split("/") for p in paths]
        max_levels = max(len(r) for r in rows)
        cols = [f"Liv {i+1}" for i in range(max_levels)]
        df = pd.DataFrame([r + [""]*(max_levels-len(r)) for r in rows], columns=cols)
        for c in cols:
            df[c] = df[c].mask(df[c] == df[c].shift(), "")
        st.table(df)

    # Download finale
    with open(zip_path, 'rb') as f:
        st.download_button(
            "Scarica file ZIP con estrazioni",
            data=f,
            file_name=output_filename,
            mime="application/zip",
            key="download_extracted_zip"
        )
