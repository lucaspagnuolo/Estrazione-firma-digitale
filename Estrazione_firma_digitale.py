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

# --- Layout con logo a destra ---------------------------------------------
col1, col2 = st.columns([7, 3])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# --- Funzione che esegue “openssl cms -verify” e legge il certificato -----
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path | None, str, bool]:
    payload_basename = p7m_file_path.stem
    output_file = output_dir / payload_basename

    # Estraggo il payload
    res1 = subprocess.run([
        "openssl", "cms", "-verify",
        "-in", str(p7m_file_path), "-inform", "DER",
        "-noverify", "-out", str(output_file)
    ], capture_output=True)
    if res1.returncode != 0:
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {res1.stderr.decode().strip()}")
        return None, "", False

    # Estraggo il certificato in PEM
    cert_pem = output_dir / f"{payload_basename}_cert.pem"
    res2 = subprocess.run([
        "openssl", "pkcs7", "-inform", "DER",
        "-in", str(p7m_file_path), "-print_certs",
        "-out", str(cert_pem)
    ], capture_output=True)
    if res2.returncode != 0:
        st.error(f"Errore estrazione certificato da «{p7m_file_path.name}»: {res2.stderr.decode().strip()}")
        return output_file, "Sconosciuto", False

    # Leggo subject e dates
    res3 = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    if res3.returncode != 0:
        st.error(f"Errore lettura info certificato: {res3.stderr.strip()}")
        return output_file, "Sconosciuto", False

    lines = res3.stdout.splitlines()
    signer = "Sconosciuto"
    for rdn in ["CN","SN","UID","emailAddress","SERIALNUMBER"]:
        m = re.search(rf"{rdn}\s*=\s*([^,\/]+)", "\n".join(lines))
        if m:
            signer = m.group(1).strip()
            break

    def _pd(ds): return datetime.strptime(ds.strip(), "%b %d %H:%M:%S %Y %Z")
    not_before = next(l for l in lines if "notBefore" in l).split("=",1)[1]
    not_after  = next(l for l in lines if "notAfter" in l).split("=",1)[1]
    valid = _pd(not_before) <= datetime.utcnow() <= _pd(not_after)

    # Rinomino se payload ZIP
    try:
        with open(output_file, "rb") as f:
            if f.read(4).startswith(b"PK\x03\x04"):
                new_zip = output_file.with_suffix('.zip')
                output_file.rename(new_zip)
                output_file = new_zip
    except:
        pass

    return output_file, signer, valid

# --- Funzione ricorsiva che scompatta tutti gli ZIP e appiattisce cartelle ---
def recursive_unpack_and_flatten(directory: Path):
    for archive in list(directory.rglob("*.zip")):
        if not archive.is_file():
            continue
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

# --- Processamento principale dei .p7m in una directory ---
def process_p7m_dir(directory: Path, indent: str = ""):
    for p7m in directory.rglob("*.p7m"):
        rel = p7m.relative_to(directory)
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        if not payload:
            continue
        p7m.unlink(missing_ok=True)
        st.write(f"{indent}– Estratto: **{payload.name}** | Firmato da: **{signer}** | Validità: {'✅' if valid else '⚠️'}")
        if payload.suffix.lower() == ".zip":
            recursive_unpack_and_flatten(payload.parent)
            new_dir = payload.parent / payload.stem
            if new_dir.is_dir():
                process_p7m_dir(new_dir, indent + "  ")
            payload.unlink(missing_ok=True)

# --- Streamlit UI e flusso principale ---
output_name = st.text_input("Nome del file ZIP di output (includi .zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploaded_files = st.file_uploader(
    "Carica file .p7m o archivi .zip contenenti .p7m",
    accept_multiple_files=True
)

if uploaded_files:
    # Cartella temporanea radice
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded in uploaded_files:
        name = uploaded.name
        ext = Path(name).suffix.lower()
        tmp_dir = Path(tempfile.mkdtemp(prefix="proc_"))
        file_path = tmp_dir / name
        file_path.write_bytes(uploaded.getbuffer())

        if ext == ".zip":
            try:
                with zipfile.ZipFile(file_path) as zf:
                    zf.extractall(tmp_dir)
            except Exception as e:
                st.error(f"Errore estrazione ZIP: {e}")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                continue
            recursive_unpack_and_flatten(tmp_dir)
            target = root_temp / file_path.stem
            # flatten directory: copia contenuti direttamente
            shutil.copytree(tmp_dir, target)
            process_p7m_dir(target)
            shutil.rmtree(tmp_dir, ignore_errors=True)

        elif ext == ".p7m":
            payload, signer, valid = extract_signed_content(file_path, root_temp)
            if payload:
                process_p7m_dir(root_temp)
            shutil.rmtree(tmp_dir, ignore_errors=True)
        else:
            st.warning(f"Ignoro {name}: estensione non supportata")

    # Creazione ZIP di output senza livello ridondante
    out_dir = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zip_path = out_dir / output_filename
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for path in root_temp.iterdir():
            if path.is_dir():
                for file in path.rglob('*'):
                    if file.is_file():
                        zf.write(file, file.relative_to(root_temp))
            elif path.is_file():
                zf.write(path, path.name)

    # Anteprima struttura ZIP
    st.subheader("Anteprima struttura ZIP risultante")
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            st.write(info.filename)

    # Pulsante di download
    with open(zip_path, 'rb') as f:
        st.download_button(
            "Scarica file ZIP con estrazioni",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
