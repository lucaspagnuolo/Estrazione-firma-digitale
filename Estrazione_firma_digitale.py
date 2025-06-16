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

    # 1) Estraggo il payload
    st.info(f"DEBUG: eseguo openssl cms -verify su {p7m_file_path.name}")
    res1 = subprocess.run([
        "openssl", "cms", "-verify",
        "-in", str(p7m_file_path), "-inform", "DER",
        "-noverify", "-out", str(output_file)
    ], capture_output=True)
    if res1.returncode != 0:
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {res1.stderr.decode().strip()}")
        return None, "", False

    # 2) Estraggo il certificato in PEM
    cert_pem = output_dir / f"{payload_basename}_cert.pem"
    st.info(f"DEBUG: eseguo openssl pkcs7 -print_certs su {p7m_file_path.name}")
    res2 = subprocess.run([
        "openssl", "pkcs7", "-inform", "DER",
        "-in", str(p7m_file_path), "-print_certs",
        "-out", str(cert_pem)
    ], capture_output=True)
    if res2.returncode != 0:
        st.error(f"Errore estrazione cert da «{p7m_file_path.name}»: {res2.stderr.decode().strip()}")
        return output_file, "Sconosciuto", False

    # 3) Leggo subject e dates
    st.info(f"DEBUG: eseguo openssl x509 su {cert_pem.name}")
    res3 = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)
    if res3.returncode != 0:
        st.error(f"Errore lettura certinfo «{cert_pem.name}»: {res3.stderr.strip()}")
        cert_pem.unlink(missing_ok=True)
        return output_file, "Sconosciuto", False
    cert_pem.unlink(missing_ok=True)

    lines = res3.stdout.splitlines()
    st.debug_msgs = []
    st.debug_msgs.append(f"DEBUG: openssl x509 output: {lines}")

    # Estrazione nome firmatario
    signer = "Sconosciuto"
    for rdn in ["CN","SN","UID","emailAddress","SERIALNUMBER"]:
        m = re.search(rf"{rdn}\s*=\s*([^,\/]+)", "\n".join(lines))
        if m:
            signer = m.group(1).strip()
            st.debug_msgs.append(f"DEBUG: trovato signer {signer} con RDN {rdn}")
            break

    # Estrazione date
    def _pd(ds): return datetime.strptime(ds.strip(), "%b %d %H:%M:%S %Y %Z")
    nb = next(l for l in lines if "notBefore" in l).split("=",1)[1]
    na = next(l for l in lines if "notAfter" in l).split("=",1)[1]
    valid = _pd(nb) <= datetime.utcnow() <= _pd(na)
    st.debug_msgs.append(f"DEBUG: notBefore={nb}, notAfter={na}, valid={valid}")

    # Debug header file
    try:
        with open(output_file, "rb") as f:
            hdr = f.read(4)
        is_zip = hdr.startswith(b"PK\x03\x04")
        st.debug_msgs.append(f"DEBUG: header {payload_basename} = {hdr}")
        if is_zip:
            newz = output_file.with_suffix('.zip')
            output_file.rename(newz)
            output_file = newz
            st.debug_msgs.append(f"DEBUG: rinominato in {newz.name}")
    except Exception as e:
        st.debug_msgs.append(f"DEBUG: lettura header fallita: {e}")

    # Mostra debug interni extract
    for msg in st.debug_msgs:
        st.info(msg)

    return output_file, signer, valid

# --- Funzione ricorsiva di unzip e flatten ---
def recursive_unpack_and_flatten(dir: Path):
    for z in list(dir.rglob("*.zip")):
        st.info(f"DEBUG: trovo ZIP {z.relative_to(dir)}")
        dest = z.parent / f"{z.stem}_unz"
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir()
        try:
            with zipfile.ZipFile(z) as zf:
                zf.extractall(dest)
            st.info(f"DEBUG: estratto {z.name} in {dest.relative_to(dir)}")
        except Exception as e:
            st.warning(f"Errore unzip {z.name}: {e}")
        z.unlink()
        # flatten
        items = list(dest.iterdir())
        if len(items)==1 and items[0].is_dir():
            for i in items[0].iterdir(): shutil.move(str(i), str(dest))
            items[0].rmdir()
        recursive_unpack_and_flatten(dest)

# --- Cleanup safe ---
def remove_dup(dir: Path):
    st.info(f"DEBUG: cleanup duplicate in {dir}")
    for root, ds, _ in os.walk(dir):
        for d in ds:
            p = Path(root)/d
            f1 = sorted(f.name for f in Path(root).iterdir() if f.is_file())
            f2 = sorted(f.name for f in p.iterdir() if f.is_file())
            if f1 == f2:
                shutil.rmtree(p)
                st.info(f"DEBUG: rimosso dup folder {p.relative_to(dir)}")

def cleanup_zipdirs(dir: Path):
    st.info(f"DEBUG: cleanup extra zip-named in {dir}")
    for root, ds, _ in os.walk(dir):
        for d in ds:
            p = Path(root)/d
            if d.lower().endswith('zip') and (p.parent/(d[:-3])).is_dir():
                shutil.rmtree(p, ignore_errors=True)
                st.info(f"DEBUG: rimosso zip-dir {p.relative_to(dir)}")

# --- Funzione principale per processare .p7m in una directory -------------
def process_p7m_dir(d: Path, log: str):
    for p7m in d.rglob('*.p7m'):
        st.info(f"DEBUG: process {p7m.relative_to(d)}")
        out, signer, valid = extract_signed_content(p7m, p7m.parent)
        if not out:
            st.warning(f"DEBUG: estrazione fallita per {p7m.name}")
            continue
        p7m.unlink(missing_ok=True)
        st.write(f"{log} · estratto {out.name} firmato da {signer} – valid={valid}")
        if out.suffix == '.zip':
            recursive_unpack_and_flatten(out.parent)
            newd = out.parent / out.stem
            if newd.is_dir():
                process_p7m_dir(newd, log + '  ')
            out.unlink(missing_ok=True)

# --- Streamlit: upload multiplo, creazione cartelle temporanee -------------
output_name = st.text_input(
    "Nome del file ZIP di output (include .zip, verrà aggiunto se manca):",
    value="all_extracted.zip"
)
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o archivi .zip contenenti .p7m",
    accept_multiple_files=True
)

if uploaded_files:
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))
    st.write(f"DEBUG: root_temp creato in {root_temp}")

    for uploaded in uploaded_files:
        name = uploaded.name
        ext = Path(name).suffix.lower()
        tmp = Path(tempfile.mkdtemp(prefix="proc_"))
        file_path = tmp / name
        file_path.write_bytes(uploaded.getbuffer())
        st.write(f"DEBUG: caricamento file {file_path}")

        if ext == ".zip":
            st.write(f"🔄 Rilevato ZIP: {name}")
            try:
                with zipfile.ZipFile(file_path) as zf:
                    zf.extractall(tmp)
                st.info(f"DEBUG: unzip completato di {name}")
            except Exception as e:
                st.error(f"Errore unzip {name}: {e}")
                shutil.rmtree(tmp, ignore_errors=True)
                continue
            recursive_unpack_and_flatten(tmp)
            target = root_temp / Path(name).stem
            shutil.copytree(tmp, target)
            st.info(f"DEBUG: copiato in target {target}")
            process_p7m_dir(target, target.name)
            shutil.rmtree(tmp, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 Rilevato P7M: {name}")
            out, signer, valid = extract_signed_content(file_path, root_temp)
            st.write(f"DEBUG: extract_signed_content={out, signer, valid}")
            if out:
                st.write(f"  – File estratto: **{out.name}**, firmato da **{signer}**, valid={valid}")
            shutil.rmtree(tmp, ignore_errors=True)

        else:
            st.warning(f"Ignoro {name}: estensione non supportata ({ext})")

    # Debug struttura prima cleanup
    st.subheader("DEBUG: struttura completa di root_temp prima cleanup")
    for p in sorted(root_temp.rglob("*")):
        st.write(f"• {p.relative_to(root_temp)}")

    remove_dup(root_temp)
    cleanup_zipdirs(root_temp)

    # Debug struttura dopo cleanup
    st.subheader("DEBUG: struttura completa di root_temp dopo cleanup")
    for p in sorted(root_temp.rglob("*")):
        st.write(f"• {p.relative_to(root_temp)}")

    # Creazione ZIP di output in cartella separata
    out_dir = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zip_base = str(out_dir / output_filename).rstrip('.zip')
    zip_path = Path(shutil.make_archive(zip_base, 'zip', str(root_temp)))
    st.success(f"ZIP creato: {zip_path}")

    # Anteprima struttura ZIP
    st.subheader("Anteprima struttura ZIP risultante")
    with zipfile.ZipFile(zip_path) as zf:
        paths = zf.namelist()
    for p in paths:
        st.write(p)

    # Download button
    with open(zip_path, 'rb') as f:
        st.download_button(
            "Scarica il file ZIP con tutte le estrazioni",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
