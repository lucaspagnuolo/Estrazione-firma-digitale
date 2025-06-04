import streamlit as st
import os
import zipfile
import tarfile
import subprocess
import tempfile
import shutil
from pathlib import Path
from PIL import Image

# Layout con logo a destra
col1, col2 = st.columns([8, 1])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=120)

def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> Path | None:
    payload_filename = p7m_file_path.stem
    output_file = output_dir / payload_filename

    result = subprocess.run(
        [
            "openssl", "cms", "-verify",
            "-in", str(p7m_file_path),
            "-inform", "DER",
            "-noverify",
            "-out", str(output_file)
        ],
        capture_output=True
    )

    if result.returncode != 0:
        st.error(f"Errore durante l’estrazione di {p7m_file_path.name}: {result.stderr.decode().strip()}")
        return None

    return output_file

def unpack_inner_archive(payload_path: Path, destination_dir: Path) -> bool:
    if zipfile.is_zipfile(payload_path):
        with zipfile.ZipFile(payload_path, "r") as zf:
            zf.extractall(destination_dir)
        payload_path.unlink()
        return True

    try:
        if tarfile.is_tarfile(payload_path):
            with tarfile.open(payload_path, "r:*") as tf:
                tf.extractall(destination_dir)
            payload_path.unlink()
            return True
    except tarfile.TarError:
        pass

    return False

# NOTA: qui rimuoviamo completamente `type=[...]` per testare se il caricamento dello ZIP funziona
uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o un file .zip contenente .p7m – prova senza filtro ‘type’",
    accept_multiple_files=True
)

if uploaded_files:
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded_file in uploaded_files:
        filename = uploaded_file.name
        suffix = Path(filename).suffix.lower()

        if suffix == ".zip":
            st.write(f"🔄 Rilevato file ZIP: {filename}")
            # Creiamo una cartella temporanea per estrarre lo ZIP
            zip_temp_dir = Path(tempfile.mkdtemp(prefix="zip_unpack_"))
            zip_path = zip_temp_dir / filename
            with open(zip_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(zip_temp_dir)
            except zipfile.BadZipFile:
                st.error(f"Errore: «{filename}» non è un archivio ZIP valido.")
                shutil.rmtree(zip_temp_dir, ignore_errors=True)
                continue

            # Scansione ricorsiva di tutti i .p7m dentro lo ZIP
            for p7m_path in zip_temp_dir.rglob("*.p7m"):
                stem = p7m_path.stem
                st.write(f"· Trovato .p7m dentro ZIP: {p7m_path.name}")

                file_dir = root_temp / stem
                file_dir.mkdir(parents=True, exist_ok=True)

                # Copia il file .p7m estratto in file_dir
                p7m_copy_path = file_dir / p7m_path.name
                shutil.copy2(p7m_path, p7m_copy_path)

                extracted_dir = file_dir / "estratto"
                extracted_dir.mkdir(exist_ok=True)

                payload_path = extract_signed_content(p7m_copy_path, extracted_dir)
                if not payload_path:
                    continue

                _ = unpack_inner_archive(payload_path, extracted_dir)

            shutil.rmtree(zip_temp_dir, ignore_errors=True)

        elif suffix == ".p7m":
            st.write(f"🔄 Rilevato file .p7m: {filename}")
            stem = Path(filename).stem
            file_dir = root_temp / stem
            file_dir.mkdir(parents=True, exist_ok=True)

            p7m_file_path = file_dir / filename
            with open(p7m_file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            extracted_dir = file_dir / "estratto"
            extracted_dir.mkdir(exist_ok=True)

            payload_path = extract_signed_content(p7m_file_path, extracted_dir)
            if not payload_path:
                continue

            _ = unpack_inner_archive(payload_path, extracted_dir)

        else:
            # Viene segnalato, ma non blocca l’intero upload
            st.warning(f"Ignoro «{filename}»: estensione non supportata ({suffix}).")

    # Alla fine, costruisco lo ZIP aggregato
    zip_file_path = root_temp / "all_extracted.zip"
    with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(root_temp):
            for file in files:
                if file == "all_extracted.zip":
                    continue
                file_path = Path(root) / file
                zipf.write(file_path, file_path.relative_to(root_temp))

    with open(zip_file_path, "rb") as f:
        st.download_button(
            label="Scarica il .zip con tutte le estrazioni",
            data=f,
            file_name=zip_file_path.name,
            mime="application/zip"
        )
