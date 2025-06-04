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
    logo = Image.open("img/Consip_Logo.png")  # Percorso relativo nella repo
    st.image(logo, width=120)

def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> Path | None:
    """
    Estrae il contenuto di un file .p7m (CAdES/CMS) usando openssl cms.
    Se il payload estratto è un archivio (ZIP o TAR), non lo scompatta qui: 
    questa funzione si limita a scrivere il payload grezzo in 'output_dir'.
    - p7m_file_path: Path al file .p7m da estrarre
    - output_dir: Path alla directory dove salvare il file estratto (payload)
    Ritorna il Path del file estratto (payload), oppure None in caso di errore.
    """
    payload_filename = p7m_file_path.stem
    output_file = output_dir / payload_filename

    result = subprocess.run(
        [
            'openssl', 'cms', '-verify',
            '-in', str(p7m_file_path),
            '-inform', 'DER',
            '-noverify',
            '-out', str(output_file)
        ],
        capture_output=True
    )

    if result.returncode != 0:
        st.error(f"Errore durante l'estrazione del file {p7m_file_path.name}: {result.stderr.decode().strip()}")
        return None

    return output_file

def unpack_inner_archive(payload_path: Path, destination_dir: Path) -> bool:
    """
    Se 'payload_path' è un archivio ZIP o TAR, lo scompatta dentro 'destination_dir'.
    Ritorna True se è stato un archivio e l'abbiamo scompattato, False altrimenti.
    Dopo lo scompattamento, elimina l'archivio originale.
    """
    if zipfile.is_zipfile(payload_path):
        with zipfile.ZipFile(payload_path, 'r') as zf:
            zf.extractall(destination_dir)
        payload_path.unlink()
        return True

    try:
        if tarfile.is_tarfile(payload_path):
            with tarfile.open(payload_path, 'r:*') as tf:
                tf.extractall(destination_dir)
            payload_path.unlink()
            return True
    except tarfile.TarError:
        pass

    return False

uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o un file .zip contenente più .p7m",
    accept_multiple_files=True,
    type=["p7m", "zip"]
)

if uploaded_files:
    # Cartella temporanea principale in cui costruire tutte le estrazioni
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded_file in uploaded_files:
        filename = uploaded_file.name
        suffix = Path(filename).suffix.lower()

        if suffix == ".zip":
            # Se è uno .zip, estraiamo temporaneamente il suo contenuto e scansioniamo tutti i .p7m al suo interno
            st.write(f"File ZIP caricato: {filename}")
            zip_temp_dir = Path(tempfile.mkdtemp(prefix="zip_unpack_"))
            zip_path = zip_temp_dir / filename
            # Salva lo ZIP su disco
            with open(zip_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(zip_temp_dir)
            except zipfile.BadZipFile:
                st.error(f"Errore: il file {filename} non è un archivio ZIP valido.")
                shutil.rmtree(zip_temp_dir, ignore_errors=True)
                continue

            # Cerca ricorsivamente tutti i .p7m dentro zip_temp_dir
            for p7m_path in zip_temp_dir.rglob("*.p7m"):
                relative_p7m_name = p7m_path.name
                stem = p7m_path.stem
                st.write(f"Trovato .p7m dentro ZIP: {relative_p7m_name}")

                # Crea una cartella per questo .p7m dentro root_temp
                file_dir = root_temp / stem
                file_dir.mkdir(parents=True, exist_ok=True)

                # Copia il .p7m nella sua directory dedicata
                p7m_copy_path = file_dir / relative_p7m_name
                shutil.copy2(p7m_path, p7m_copy_path)

                # Crea cartella "estratto" e procede con estrazione
                extracted_dir = file_dir / "estratto"
                extracted_dir.mkdir(exist_ok=True)

                payload_path = extract_signed_content(p7m_copy_path, extracted_dir)
                if not payload_path:
                    continue

                _ = unpack_inner_archive(payload_path, extracted_dir)

            # Pulisci la cartella temporanea usata per lo ZIP
            shutil.rmtree(zip_temp_dir, ignore_errors=True)

        elif suffix == ".p7m":
            # Se è un .p7m caricato direttamente
            st.write(f"File .p7m caricato: {filename}")
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
            st.warning(f"I file di tipo '{suffix}' non sono supportati e verranno ignorati.")

    # Una volta processati tutti i .p7m (diretti o dentro ZIP), creiamo l'archivio finale
    zip_file_path = root_temp / "all_extracted.zip"
    with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(root_temp):
            for file in files:
                if file == "all_extracted.zip":
                    continue
                file_path = Path(root) / file
                # Mainteniamo la struttura relativa dentro lo ZIP finale
                zipf.write(file_path, file_path.relative_to(root_temp))

    # Renderizza il pulsante di download per lo ZIP aggregato
    with open(zip_file_path, "rb") as f:
        st.download_button(
            label="Scarica un unico zip con tutte le cartelle estratte",
            data=f,
            file_name=zip_file_path.name,
            mime="application/zip"
        )
