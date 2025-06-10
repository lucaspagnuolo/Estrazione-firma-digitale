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

# --- Layout con logo a destra ---------------------------------------------
col1, col2 = st.columns([7, 3])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# --- Funzione che esegue “openssl cms -verify” e legge il certificato -----
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path | None, str, bool]:
    """
    Estrae il payload di un .p7m, estrae il certificato (rimuovendo subito il .pem),
    e ritorna (output_file, signer_name, is_valid). Se il payload risultante
    è un vero ZIP (verificandone gli header), lo rinomina aggiungendo “.zip”.
    """
    payload_basename = p7m_file_path.stem
    output_file = output_dir / payload_basename

    # 1) Estraggo il payload (file “grezzo”) con openssl cms -verify
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

    # 2) Estraggo il certificato in PEM, leggo subject/dates, poi elimino il .pem
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

    cmd3 = [
        "openssl", "x509",
        "-in", str(cert_pem_path),
        "-noout",
        "-subject",
        "-dates"
    ]
    res3 = subprocess.run(cmd3, capture_output=True, text=True)
    if res3.returncode != 0:
        st.error(f"Errore lettura info certificato da «{cert_pem_path.name}»: {res3.stderr.strip()}")
        try:
            cert_pem_path.unlink()
        except:
            pass
        return output_file, "Sconosciuto", False

    try:
        cert_pem_path.unlink()
    except:
        pass

    lines = res3.stdout.splitlines()
    subject_line = lines[0]
    candidato_rdn = ["CN", "SN", "UID", "emailAddress", "SERIALNUMBER"]
    signer_name = "Sconosciuto"
    for rdn in candidato_rdn:
        m = re.search(rf"{rdn}\s*=\s*([^,/]+)", subject_line)
        if m:
            signer_name = m.group(1).strip()
            break

    def parse_openssl_date(s: str) -> datetime:
        return datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z")

    not_before = parse_openssl_date(lines[1].split("=", 1)[1])
    not_after = parse_openssl_date(lines[2].split("=", 1)[1])
    now = datetime.utcnow()
    is_valid = (not_before <= now <= not_after)

    try:
        with open(output_file, "rb") as f:
            header = f.read(4)
        if header.startswith(b"PK\x03\x04"):
            new_zip = output_file.with_suffix(".zip")
            output_file.rename(new_zip)
            output_file = new_zip
    except:
        pass

    return output_file, signer_name, is_valid

# --- Funzione ricorsiva che scompatta tutti gli ZIP e appiattisce cartelle ---
def recursive_unpack_and_flatten(directory: Path):
    """
    Per ogni file “*.zip” in modo ricorsivo sotto `directory`, estrae
    in una cartella con lo stesso nome (ma senza il suffisso “zip”, se presente),
    poi:
      - se quella cartella contiene esattamente UNA sottocartella senza altri file,
        appiattisce il contenuto (sposta le sottocartelle nella cartella padre),
        eliminando quindi un livello di directory.
      - elimina l’archivio .zip di partenza.
    Ripete finché non rimangano più *.zip in ogni livello.
    """
    for archive_path in list(directory.rglob("*.zip")):
        if not archive_path.is_file():
            continue

        parent_folder = archive_path.parent
        raw_name = archive_path.stem
        if raw_name.lower().endswith("zip"):
            raw_name = raw_name[:-3]

        extract_folder = parent_folder / raw_name
        if extract_folder.exists() and extract_folder.is_file():
            extract_folder.unlink()
        extract_folder.mkdir(exist_ok=True)

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(extract_folder)
        except zipfile.BadZipFile:
            st.warning(f"Attenzione: «{archive_path.name}» non è un archivio ZIP valido.")
            archive_path.unlink(missing_ok=True)
            continue

        archive_path.unlink(missing_ok=True)
        items = list(extract_folder.iterdir())
        if len(items) == 1 and items[0].is_dir():
            lone_sub = items[0]
            for sub_item in lone_sub.iterdir():
                shutil.move(str(sub_item), str(extract_folder))
            lone_sub.rmdir()

        recursive_unpack_and_flatten(extract_folder)

# --- Procedura principale: processa ogni directory cercando .p7m ----------
def process_directory_for_p7m(directory: Path, log_root: str):
    """
    Cerca in `directory` tutti i file “*.p7m” (a ogni livello) e, per ognuno:
      1) chiama extract_signed_content su quel file, mettendo il payload
         (pdf o zip) nella stessa cartella in cui si trovava il .p7m.
      2) elimina il .p7m originale.
      3) se il payload estratto era un .zip, lo scompatta con
         recursive_unpack_and_flatten() nella sua cartella e poi
         richiama ricorsivamente process_directory_for_p7m() dentro
         la sottocartella appena creata, in modo da processare eventuali
         .p7m ancora più in profondità.
      4) logga in UI chi ha firmato e lo stato di validità.
    """
    for p7m_path in list(directory.rglob("*.p7m")):
        rel = p7m_path.relative_to(directory)
        st.write(f"{log_root} · Trovato .p7m in **{rel.parent}**: {p7m_path.name}")

        payload_path, signer_name, firma_ok = extract_signed_content(p7m_path, p7m_path.parent)
        if not payload_path:
            continue

        try:
            p7m_path.unlink()
        except:
            pass

        if payload_path.suffix.lower() == ".zip":
            # Appiattimento e estrazione all'interno della stessa cartella
            recursive_unpack_and_flatten(payload_path.parent)
            nuova_cartella = payload_path.parent / payload_path.stem
            if nuova_cartella.exists() and nuova_cartella.is_dir():
                process_directory_for_p7m(nuova_cartella, log_root + "  ")
            try:
                payload_path.unlink()
            except:
                pass

        colx, coly = st.columns([4, 1])
        with colx:
            st.write(f"  – File estratto: **{payload_path.stem + payload_path.suffix}**")
            st.write(f"    Firmato da: **{signer_name}**")
        with coly:
            if firma_ok:
                st.success("Firma valida ✅")
            else:
                st.error("Firma NON valida ⚠️")

# --- Funzione di “cleanup” per rimuovere directory con soli .p7m non processati ---
def cleanup_unprocessed_p7m_dirs(root_dir: Path):
    all_dirs = sorted(
        (p for p in root_dir.rglob("*") if p.is_dir()),
        key=lambda d: len(str(d).split(os.sep)),
        reverse=True
    )
    for d in all_dirs:
        files = [f for f in d.iterdir() if f.is_file()]
        if files and all(f.suffix.lower() == ".p7m" for f in files):
            for f in files:
                try:
                    f.unlink()
                except:
                    pass
            try:
                d.rmdir()
            except:
                pass

# --- Nuova funzione di “cleanup” per rimuovere cartelle che terminano con “zip” ---
def cleanup_extra_zip_named_dirs(root_dir: Path):
    all_dirs = sorted(
        (d for d in root_dir.rglob("*") if d.is_dir()),
        key=lambda d: len(str(d).split(os.sep)),
        reverse=True
    )
    for d in all_dirs:
        if d.name.lower().endswith("zip"):
            sibling_name = d.name[:-3]
            sibling = d.parent / sibling_name
            if sibling.exists() and sibling.is_dir():
                shutil.rmtree(d, ignore_errors=True)

# --- Streamlit: upload multiplo, creazione cartelle temporanee -------------
output_name = st.text_input(
    "Nome del file ZIP di output (includi “.zip” o sarà aggiunto automaticamente):",
    value="all_extracted.zip"
)
if output_name.strip().lower().endswith(".zip"):
    output_filename = output_name.strip()
else:
    output_filename = output_name.strip() + ".zip"

uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o archivi .zip contenenti .p7m",
    accept_multiple_files=True
)

if uploaded_files:
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded_file in uploaded_files:
        nome = uploaded_file.name
        suff = Path(nome).suffix.lower()

        if suff == ".zip":
            st.write(f"🔄 Rilevato file ZIP: {nome}")
            temp_zip_dir = Path(tempfile.mkdtemp(prefix="zip_unpack_"))
            zip_path = temp_zip_dir / nome
            with open(zip_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(temp_zip_dir)
            except zipfile.BadZipFile:
                st.error(f"Errore: «{nome}» non è un archivio ZIP valido.")
                shutil.rmtree(temp_zip_dir, ignore_errors=True)
                continue

            items = [p for p in temp_zip_dir.iterdir() if p != zip_path]
            if len(items) == 1 and items[0].is_dir():
                base_dir = items[0]
            else:
                base_dir = temp_zip_dir

            # Copio TUTTO (cartelle e file) da base_dir → root_temp/<nome_base_zip>/
            nome_base = zip_path.stem
            target_root_for_this_zip = root_temp / nome_base
            shutil.copytree(base_dir, target_root_for_this_zip)

            # Processiamo eventuali .p7m dentro target_root_for_this_zip
            process_directory_for_p7m(target_root_for_this_zip, f"{nome_base}")

            # Cleanup cartelle con soli .p7m e cartelle “*.zip” ridondanti
            cleanup_unprocessed_p7m_dirs(target_root_for_this_zip)
            cleanup_extra_zip_named_dirs(target_root_for_this_zip)

            shutil.rmtree(temp_zip_dir, ignore_errors=True)

        elif suff == ".p7m":
            st.write(f"🔄 Rilevato file .p7m: {nome}")

            temp_single = Path(tempfile.mkdtemp(prefix="single_p7m_"))
            p7m_path = temp_single / nome
            with open(p7m_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            payload_path, signer_name, firma_ok = extract_signed_content(p7m_path, root_temp)
            if not payload_path:
                shutil.rmtree(temp_single, ignore_errors=True)
                continue

            try:
                p7m_path.unlink()
            except:
                pass

            if payload_path.suffix.lower() == ".zip":
                recursive_unpack_and_flatten(root_temp)
                for subd in root_temp.iterdir():
                    if subd.is_dir():
                        process_directory_for_p7m(subd, subd.name)
                cleanup_unprocessed_p7m_dirs(root_temp)
                cleanup_extra_zip_named_dirs(root_temp)
                try:
                    payload_path.unlink()
                except:
                    pass

            colx, coly = st.columns([4, 1])
            with colx:
                st.write(f"  – File estratto: **{payload_path.name}**")
                st.write(f"    Firmato da: **{signer_name}**")
            with coly:
                if firma_ok:
                    st.success("Firma valida ✅")
                else:
                    st.error("Firma NON valida ⚠️")

            shutil.rmtree(temp_single, ignore_errors=True)

    # Creo lo ZIP di output con tutta la struttura "pulita"
    zip_out_path = root_temp / output_filename
    with zipfile.ZipFile(zip_out_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(root_temp):
            for file in files:
                if file == output_filename:
                    continue
                file_path = Path(root) / file
                rel_path = file_path.relative_to(root_temp)
                zipf.write(file_path, rel_path)

    with open(zip_out_path, "rb") as f:
        st.download_button(
            label="Scarica il file ZIP con tutte le estrazioni",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
