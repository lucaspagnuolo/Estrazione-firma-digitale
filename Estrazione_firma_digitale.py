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
    cmd1 = [
        "openssl", "cms", "-verify",
        "-in", str(p7m_file_path),
        "-inform", "DER",
        "-noverify",
        "-out", str(output_file)
    ]
    res1 = subprocess.run(cmd1, capture_output=True)
    if res1.returncode != 0:
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {res1.stderr.decode().strip()}")
        return None, "", False

    # 2) Rinomino se è un vero ZIP
    try:
        with open(output_file, "rb") as f:
            if f.read(4).startswith(b"PK\x03\x04"):
                new_zip = output_file.with_suffix(".zip")
                output_file.rename(new_zip)
                output_file = new_zip
    except:
        pass

    # 3) Estraggo il certificato in PEM
    cert_pem_path = output_dir / f"{payload_basename}_cert.pem"
    cmd2 = [
        "openssl", "pkcs7",
        "-inform", "DER",
        "-in", str(p7m_file_path),
        "-print_certs",
        "-out", str(cert_pem_path)
    ]
    if subprocess.run(cmd2, capture_output=True).returncode != 0:
        return output_file, "Sconosciuto", False

    # 4) Leggo subject e dates
    cmd3 = [
        "openssl", "x509",
        "-in", str(cert_pem_path),
        "-noout",
        "-subject",
        "-dates"
    ]
    res3 = subprocess.run(cmd3, capture_output=True, text=True)
    cert_pem_path.unlink(missing_ok=True)
    if res3.returncode != 0:
        return output_file, "Sconosciuto", False

    txt = res3.stdout
    signer = "Sconosciuto"
    for rdn in ["CN", "emailAddress"]:
        m = re.search(rf"{rdn}=([^,/]+)", txt)
        if m:
            signer = m.group(1).strip()
            break

    def parse_date(s): return datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z")
    lines = txt.splitlines()
    not_before = parse_date(next(l for l in lines if "notBefore" in l).split("=",1)[1])
    not_after  = parse_date(next(l for l in lines if "notAfter" in l).split("=",1)[1])
    is_valid = (not_before <= datetime.utcnow() <= not_after)

    return output_file, signer, is_valid

# --- Unpack ricorsivo ------------------------------------------------------
def recursive_unpack_and_flatten(directory: Path):
    for z in list(directory.rglob("*.zip")):
        if not z.is_file():
            continue
        dest = z.with_suffix("_unzipped")
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir()
        try:
            with zipfile.ZipFile(z, "r") as zf:
                zf.extractall(dest)
        except:
            z.unlink(missing_ok=True)
            continue
        z.unlink()
        # Se c'è un'unica subdir, sposta il suo contenuto
        items = list(dest.iterdir())
        if len(items) == 1 and items[0].is_dir():
            for it in items[0].iterdir():
                shutil.move(str(it), str(dest))
            items[0].rmdir()
        # Ricorsione
        recursive_unpack_and_flatten(dest)

# --- Processa .p7m in una directory ---------------------------------------
def process_directory_for_p7m(directory: Path, log_root: str):
    for p7m in directory.rglob("*.p7m"):
        rel = p7m.relative_to(directory)
        st.write(f"{log_root} · {rel.parent}: {p7m.name}")
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        p7m.unlink(missing_ok=True)
        if not payload:
            continue
        if payload.suffix.lower() == ".zip":
            # unpack e ricorsione
            recursive_unpack_and_flatten(payload.parent)
            sub = payload.parent / payload.stem
            if sub.is_dir():
                process_directory_for_p7m(sub, log_root + "  ")
            payload.unlink()
        c1, c2 = st.columns([4, 1])
        with c1:
            st.write(f"– Estratto: **{payload.name}**")
            st.write(f"  Firmato da: **{signer}**")
        with c2:
            if valid:
                st.success("Firma valida ✅")
            else:
                st.error("Firma NON valida ⚠️")

# --- Streamlit: caricamento e creazione ZIP finale ------------------------
output_name = st.text_input("Nome ZIP output:", "all_extracted.zip")
if not output_name.lower().endswith(".zip"):
    output_name += ".zip"

uploaded_files = st.file_uploader("Carica .zip o .p7m", accept_multiple_files=True)
if uploaded_files:
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    # Estrai tutto in root_temp
    for uploaded in uploaded_files:
        ext = Path(uploaded.name).suffix.lower()
        tmp = Path(tempfile.mkdtemp(prefix="up_"))
        fpath = tmp / uploaded.name
        fpath.write_bytes(uploaded.getbuffer())

        if ext == ".zip":
            with zipfile.ZipFile(fpath, "r") as zf:
                zf.extractall(tmp)
            recursive_unpack_and_flatten(tmp)
            for d in tmp.iterdir():
                if d.is_dir():
                    shutil.copytree(d, root_temp / d.name, dirs_exist_ok=True)

        elif ext == ".p7m":
            # estrai direttamente nella root
            extract_signed_content(fpath, root_temp)

        shutil.rmtree(tmp, ignore_errors=True)

    # Processa tutte le directory in root_temp
    for d in root_temp.iterdir():
        if d.is_dir():
            process_directory_for_p7m(d, d.name)

    # Crea ZIP finale, escludendo tutte le cartelle *_unzipped
    out_folder = Path(tempfile.mkdtemp(prefix="out_"))
    zip_out = out_folder / output_name
    with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as zf:
        for base, dirs, files in os.walk(root_temp):
            # rimuove dalla traversata le cartelle wrapper
            dirs[:] = [d for d in dirs if not d.endswith("_unzipped")]
            for f in files:
                fp = Path(base) / f
                rel = fp.relative_to(root_temp)
                zf.write(fp, rel.as_posix())

    # Bottone di download
    with open(zip_out, "rb") as f:
        st.download_button(
            label="Scarica ZIP",
            data=f,
            file_name=output_name,
            mime="application/zip"
        )

    # Anteprima struttura
    st.subheader("Anteprima struttura ZIP")
    with zipfile.ZipFile(zip_out, "r") as preview_zf:
        paths = [info.filename for info in preview_zf.infolist()]
    split_paths = [p.split("/") for p in paths]
    max_levels = max(len(parts) for parts in split_paths)
    col_names = [f"Livello {i+1}" for i in range(max_levels)]
    rows = [parts + [""] * (max_levels - len(parts)) for parts in split_paths]
    df = pd.DataFrame(rows, columns=col_names)
    for col in col_names:
        df[col] = df[col].mask(df[col] == df[col].shift(), "")
    st.table(df)
