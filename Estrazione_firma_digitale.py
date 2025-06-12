import streamlit as st
import os
import zipfile
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import re
from PIL import Image
import pandas as pd

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

    # 2) Estraggo il certificato in PEM
    cert_pem_path = output_dir / (payload_basename + "_cert.pem")
    cmd2 = [
        "openssl", "pkcs7",
        "-inform", "DER",
        "-in", str(p7m_file_path),
        "-print_certs",
        "-out", str(cert_pem_path)
    ]
    res2 = subprocess.run(cmd2, capture_output=True)
    if res2.returncode != 0:
        st.error(f"Errore estrazione certificato da «{p7m_file_path.name}»: {res2.stderr.decode().strip()}")
        return output_file, "Sconosciuto", False

    # 3) Leggo subject e dates
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
        st.error(f"Errore lettura info certificato da «{cert_pem_path.name}»: {res3.stderr.strip()}")
        return output_file, "Sconosciuto", False

    lines = res3.stdout.splitlines()
    signer_name = "Sconosciuto"
    for rdn in ["CN", "SN", "UID", "emailAddress", "SERIALNUMBER"]:
        m = re.search(rf"{rdn}\s*=\s*([^,/]+)", "\n".join(lines))
        if m:
            signer_name = m.group(1).strip()
            break

    def parse_openssl_date(date_str: str) -> datetime:
        return datetime.strptime(date_str.strip(), "%b %d %H:%M:%S %Y %Z")

    try:
        not_before = parse_openssl_date(next(l for l in lines if "notBefore" in l).split("=", 1)[1])
        not_after  = parse_openssl_date(next(l for l in lines if "notAfter"  in l).split("=", 1)[1])
        now = datetime.utcnow()
        is_valid = (not_before <= now <= not_after)
    except Exception:
        is_valid = False

    # 4) Se è veramente uno ZIP, rinomino
    try:
        with open(output_file, "rb") as f:
            hdr = f.read(4)
        if hdr.startswith(b"PK\x03\x04"):
            new_zip = output_file.with_suffix(".zip")
            output_file.rename(new_zip)
            output_file = new_zip
    except:
        pass

    return output_file, signer_name, is_valid

# --- Funzione ricorsiva che scompatta tutti gli ZIP e appiattisce cartelle ---
def recursive_unpack_and_flatten(directory: Path):
    for archive_path in list(directory.rglob("*.zip")):
        if not archive_path.is_file():
            continue
        extract_folder = archive_path.parent / f"{archive_path.stem}_unzipped"
        if extract_folder.exists() and extract_folder.is_file():
            extract_folder.unlink()
        extract_folder.mkdir(exist_ok=True)

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                for member in zf.infolist():
                    try:
                        zf.extract(member, extract_folder)
                    except (EOFError, zipfile.BadZipFile):
                        st.warning(f"Salto file corrotto «{member.filename}» in «{archive_path.name}»")
        except Exception as e:
            st.warning(f"Errore estraendo «{archive_path.name}»: {e}")
            archive_path.unlink(missing_ok=True)
            continue

        archive_path.unlink(missing_ok=True)
        items = list(extract_folder.iterdir())
        if len(items) == 1 and items[0].is_dir():
            lone = items[0]
            for it in lone.iterdir():
                shutil.move(str(it), str(extract_folder))
            lone.rmdir()

        recursive_unpack_and_flatten(extract_folder)

# --- Funzioni di utilità per gestione duplicati ---
def compare_directories(dir1: Path, dir2: Path) -> bool:
    f1 = sorted(f.name for f in dir1.iterdir() if f.is_file())
    f2 = sorted(f.name for f in dir2.iterdir() if f.is_file())
    return f1 == f2

def remove_duplicate_folders(root_dir: Path):
    for dp, dn, _ in os.walk(root_dir):
        for d in dn:
            p = Path(dp) / d
            if compare_directories(Path(dp), p):
                shutil.rmtree(p)

# --- Funzione principale per processare .p7m in una directory -------------
def process_directory_for_p7m(directory: Path, log_root: str):
    for p7m in list(directory.rglob("*.p7m")):
        rel = p7m.relative_to(directory)
        st.write(f"{log_root} · Trovato .p7m in **{rel.parent}**: {p7m.name}")

        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        st.write(f"→ extract_signed_content ha restituito: payload={payload}, signer={signer}, valid={valid}")
        if not payload:
            continue
        p7m.unlink(missing_ok=True)

        if payload.suffix.lower() == ".zip":
            recursive_unpack_and_flatten(payload.parent)
            new_dir = payload.parent / payload.stem
            if new_dir.is_dir():
                process_directory_for_p7m(new_dir, log_root + "  ")
            payload.unlink(missing_ok=True)

        c1, c2 = st.columns([4, 1])
        with c1:
            st.write(f"  – File estratto: **{payload.name}**")
            st.write(f"    Firmato da: **{signer}**")
        with c2:
            if valid:
                st.success("Firma valida ✅")
            else:
                st.error("Firma NON valida ⚠️")

# --- Cleanup di cartelle con soli .p7m non processati --------------------
def cleanup_unprocessed_p7m_dirs(root_dir: Path):
    dirs = sorted(
        (p for p in root_dir.rglob("*") if p.is_dir()),
        key=lambda d: len(str(d).split(os.sep)),
        reverse=True
    )
    for d in dirs:
        files = [f for f in d.iterdir() if f.is_file()]
        if files and all(f.suffix.lower() == ".p7m" for f in files):
            for f in files:
                f.unlink(missing_ok=True)
            d.rmdir()

# --- Cleanup di cartelle “*.zip” ridondanti -------------------------------
def cleanup_extra_zip_named_dirs(root_dir: Path):
    dirs = sorted(
        (p for p in root_dir.rglob("*") if p.is_dir()),
        key=lambda d: len(str(d).split(os.sep)),
        reverse=True
    )
    for d in dirs:
        if d.name.lower().endswith("zip"):
            sib = d.parent / d.name[:-3]
            if sib.is_dir():
                shutil.rmtree(d, ignore_errors=True)

# --- Streamlit: upload multiplo, creazione cartelle temporanee -------------
output_name = st.text_input(
    "Nome del file ZIP di output (includi “.zip” o sarà aggiunto automaticamente):",
    value="all_extracted.zip"
)
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o archivi .zip contenenti .p7m",
    accept_multiple_files=True
)

if uploaded_files:
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded in uploaded_files:
        name = uploaded.name
        ext = Path(name).suffix.lower()

        if ext == ".zip":
            st.write(f"🔄 Rilevato file ZIP: {name}")
            tmp = Path(tempfile.mkdtemp(prefix="zip_unpack_"))
            zp = tmp / name
            with open(zp, "wb") as f:
                f.write(uploaded.getbuffer())

            try:
                with zipfile.ZipFile(zp, "r") as zf:
                    inner_zips = [n for n in zf.namelist() if n.lower().endswith(".zip")]
                    if len(inner_zips) == 1:
                        inner = inner_zips[0]
                        data = zf.read(inner)
                        target_inner = tmp / Path(inner).name
                        target_inner.write_bytes(data)
                        with zipfile.ZipFile(target_inner, "r") as inner_zf:
                            inner_zf.extractall(tmp)
                        zp = target_inner
                    else:
                        zf.extractall(tmp)
            except (zipfile.BadZipFile, EOFError) as e:
                st.error(f"Errore estrazione ZIP «{name}»: {e}")
                shutil.rmtree(tmp, ignore_errors=True)
                continue

            recursive_unpack_and_flatten(tmp)
            target = root_temp / zp.stem
            shutil.copytree(tmp, target)
            process_directory_for_p7m(target, zp.stem)
            cleanup_unprocessed_p7m_dirs(target)
            cleanup_extra_zip_named_dirs(target)
            shutil.rmtree(tmp, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 Rilevato file .p7m: {name}")
            tmp = Path(tempfile.mkdtemp(prefix="single_p7m_"))
            p7m_path = tmp / name
            with open(p7m_path, "wb") as f:
                f.write(uploaded.getbuffer())

            payload, signer, valid = extract_signed_content(p7m_path, root_temp)
            st.write(f"→ extract_signed_content ha restituito: payload={payload}, signer={signer}, valid={valid}")
            if payload:
                p7m_path.unlink(missing_ok=True)
                if payload.suffix.lower() == ".zip":
                    recursive_unpack_and_flatten(root_temp)
                    for d in root_temp.iterdir():
                        if d.is_dir():
                            process_directory_for_p7m(d, d.name)
                    cleanup_unprocessed_p7m_dirs(root_temp)
                    cleanup_extra_zip_named_dirs(root_temp)
                    payload.unlink(missing_ok=True)

                c1, c2 = st.columns([4, 1])
                with c1:
                    st.write(f"  – File estratto: **{payload.name}**")
                    st.write(f"    Firmato da: **{signer}**")
                with c2:
                    if valid:
                        st.success("Firma valida ✅")
                    else:
                        st.error("Firma NON valida ⚠️")

            shutil.rmtree(tmp, ignore_errors=True)

        else:
            st.warning(f"Ignoro «{name}»: estensione non supportata ({ext}).")

    # *** DEBUG: dump struttura di root_temp ***
    st.write("🛠 Debug: struttura interna di root_temp:")
    for root, dirs, files in os.walk(root_temp):
        indent = "  " * len(Path(root).relative_to(root_temp).parts)
        st.write(f"{indent}- {Path(root).name}/")
        for f in files:
            st.write(f"{indent}    - {f}")

    # --- Raccolgo tutti i file prima della zip ------------------------
    all_files = []
    for root, _, files in os.walk(root_temp):
        for f in files:
            if f == output_filename:
                continue
            all_files.append(Path(root) / f)

    if not all_files:
        st.error("❌ Nessun file estratto: controlla che i .p7m contengano payload validi e che non ci siano stati errori in OpenSSL.")
    else:
        st.write("📦 File che sto per mettere dentro l'archivio:")
        for p in all_files:
            st.write(f"  - {p.relative_to(root_temp)}")

        # --- Creazione del file ZIP -------------------
        zip_base = tempfile.mktemp(prefix="extracted_")
        shutil.make_archive(zip_base, 'zip', root_temp)
        zip_out = Path(f"{zip_base}.zip")

        # Anteprima strutturale (solo se ci sono file)
        with zipfile.ZipFile(zip_out, "r") as preview_zf:
            paths = [info.filename for info in preview_zf.infolist()]

        if paths:
            split_paths = [p.split("/") for p in paths]
            max_levels = max(len(parts) for parts in split_paths)
            col_names = [f"Livello {i+1}" for i in range(max_levels)]
            rows = [parts + [""]*(max_levels - len(parts)) for parts in split_paths]
            df = pd.DataFrame(rows, columns=col_names)
            for col in col_names:
                df[col] = df[col].mask(df[col] == df[col].shift(), "")
            st.subheader("Anteprima strutturale del file ZIP risultante")
            st.table(df)
        else:
            st.info("📂 Anteprima: lo ZIP è vuoto, niente da mostrare.")

        # Bottone di download
        with open(zip_out, "rb") as f:
            st.download_button(
                label="Scarica il file ZIP con tutte le estrazioni",
                data=f,
                file_name=output_filename,
                mime="application/zip"
            )
