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

# --- Costanti per TSL -----------------------------------------------------
TSL_FILE    = Path("img/TSL-IT.xml")
TRUST_PEM   = Path("trust_store.pem")

def build_trust_store(tsl_path: Path, out_pem: Path):
    """
    Estrae tutti i certificati da TSL‑IT.xml e li concatena in un unico PEM
    """
    ns = {
        'tsl': 'http://uri.etsi.org/02231/v2#',
        'ds':  'http://www.w3.org/2000/09/xmldsig#'
    }
    tree = ET.parse(tsl_path)
    root = tree.getroot()
    with open(out_pem, 'wb') as f:
        # Scorri tutti i ServiceDigitalIdentity e prendi il tag X509Certificate
        for sd in root.findall('.//tsl:ServiceDigitalIdentity', ns):
            for cert in sd.findall('.//ds:X509Certificate', ns):
                cert_b64 = cert.text.strip()
                pem = (
                    b"-----BEGIN CERTIFICATE-----\n"
                    + cert_b64.encode('ascii')
                    + b"\n-----END CERTIFICATE-----\n\n"
                )
                f.write(pem)

# --- Build del trust store all’avvio -------------------------------------
if not TRUST_PEM.exists():
    build_trust_store(TSL_FILE, TRUST_PEM)

# --- Layout con logo a destra ---------------------------------------------
col1, col2 = st.columns([7, 3])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# --- Funzione per estrarre contenuto firmato e certificato ----------------
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path | None, str, bool]:
    payload_basename = p7m_file_path.stem
    output_file = output_dir / payload_basename

    # 1) Estraggo payload verificando la firma contro trust_store.pem
    res1 = subprocess.run([
        "openssl", "cms", "-verify",
        "-in", str(p7m_file_path), "-inform", "DER",
        "-CAfile", str(TRUST_PEM),
        "-out", str(output_file)
    ], capture_output=True)
    if res1.returncode != 0:
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {res1.stderr.decode().strip()}")
        return None, "", False

    # 2) Estraggo certificato
    cert_pem = output_dir / f"{payload_basename}_cert.pem"
    res2 = subprocess.run([
        "openssl", "pkcs7", "-inform", "DER",
        "-in", str(p7m_file_path), "-print_certs",
        "-out", str(cert_pem)
    ], capture_output=True)
    if res2.returncode != 0:
        st.error(f"Errore estrazione certificato da «{p7m_file_path.name}»: {res2.stderr.decode().strip()}")
        return output_file, "Sconosciuto", False

    # 3) Leggo subject e dates
    res3 = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    if res3.returncode != 0:
        st.error(f"Errore lettura info certificato: {res3.stderr.strip()}")
        return output_file, "Sconosciuto", False

    lines = res3.stdout.splitlines()
    subject_text = "\n".join(lines)
    signer = "Sconosciuto"
    for rdn in ["CN","SN","UID","emailAddress","SERIALNUMBER"]:
        m = re.search(rf"{rdn}\s*=\s*([^,/]+)", subject_text)
        if m:
            signer = m.group(1).strip()
            break

    def _pd(ds): return datetime.strptime(ds.strip(), "%b %d %H:%M:%S %Y %Z")
    not_before = next(l for l in lines if "notBefore" in l).split("=",1)[1]
    not_after  = next(l for l in lines if "notAfter" in l).split("=",1)[1]
    valid = _pd(not_before) <= datetime.utcnow() <= _pd(not_after)

    # 4) Rinomino se ZIP
    try:
        with open(output_file, "rb") as f:
            if f.read(4).startswith(b"PK\x03\x04"):
                new_zip = output_file.with_suffix('.zip')
                output_file.rename(new_zip)
                output_file = new_zip
    except:
        pass

    return output_file, signer, valid

# --- Funzione ricorsiva per ZIP annidati ----------------------------------
def recursive_unpack_and_flatten(directory: Path):
    for archive in list(directory.rglob("*.zip")):
        if not archive.is_file(): continue
        extract_folder = archive.parent / f"{archive.stem}_unz"
        shutil.rmtree(extract_folder, ignore_errors=True)
        extract_folder.mkdir()
        try:
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(extract_folder)
        except Exception:
            archive.unlink(missing_ok=True)
            continue
        archive.unlink(missing_ok=True)
        items = list(extract_folder.iterdir())
        if len(items) == 1 and items[0].is_dir():
            lone = items[0]
            for it in lone.iterdir():
                shutil.move(str(it), extract_folder)
            lone.rmdir()
        recursive_unpack_and_flatten(extract_folder)

# --- Elaborazione ricorsiva dei .p7m --------------------------------------
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
                        target_inner = tmp / Path(inner_zips[0]).name
                        target_inner.write_bytes(data)
                        with zipfile.ZipFile(target_inner) as izf:
                            izf.extractall(tmp)
                        payload.unlink(missing_ok=True)
                        archive = target_inner
                    else:
                        zf.extractall(tmp)
                        payload.unlink(missing_ok=True)
                        archive = None
            except Exception:
                st.error(f"Errore estrazione ZIP interno di {payload.name}")
                continue
            recursive_unpack_and_flatten(tmp)
            new_dir = tmp / payload.stem
            if new_dir.is_dir():
                process_p7m_dir(new_dir, indent + "  ")

# --- Streamlit UI e flusso principale ------------------------------------
output_name = st.text_input("Nome del file ZIP di output (includi .zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploaded_files = st.file_uploader(
    "Carica file .p7m o archivi .zip contenenti .p7m",
    accept_multiple_files=True
)

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
                    inner_zips = [n for n in zf.namelist() if n.lower().endswith('.zip')]
                    if len(inner_zips) == 1:
                        data = zf.read(inner_zips[0])
                        target_inner = tmp_dir / Path(inner_zips[0]).name
                        target_inner.write_bytes(data)
                        with zipfile.ZipFile(target_inner) as izf:
                            izf.extractall(tmp_dir)
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

    # Rimozione cartelle `_unz` residue
    for dir_unz in root_temp.rglob('*_unz'):
        shutil.rmtree(dir_unz, ignore_errors=True)

    # Rimuovo TUTTI i file .p7m residui
    for p7m_file in root_temp.rglob("*.p7m"):
        p7m_file.unlink(missing_ok=True)

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
        paths = [
            info.filename
            for info in zf.infolist()
            if '_unz' not in info.filename and not info.filename.lower().endswith('.p7m')
        ]
    if paths:
        split_paths = [p.split("/") for p in paths]
        max_levels = max(len(parts) for parts in split_paths)
        col_names = [f"Liv {i+1}" for i in range(max_levels)]
        rows = [parts + [""]*(max_levels - len(parts)) for parts in split_paths]
        df = pd.DataFrame(rows, columns=col_names)
        for col in col_names:
            df[col] = df[col].mask(df[col] == df[col].shift(), "")
        st.table(df)

    # Download del ZIP finale
    with open(zip_path, 'rb') as f:
        st.download_button(
            "Scarica file ZIP con estrazioni",
            data=f,
            file_name=output_filename,
            mime="application/zip",
            key="download_extracted_zip"
        )
