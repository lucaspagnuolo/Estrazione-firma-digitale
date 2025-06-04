import streamlit as st
import os
import zipfile
import tarfile
import subprocess
import tempfile
import shutil
from pathlib import Path
from PIL import Image

# --- Layout con logo a destra ---------------------------------------------
col1, col2 = st.columns([8, 1])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")  # Percorso relativo nella repo
    st.image(logo, width=120)

# --- Funzione che esegue il cms -verify di OpenSSL ------------------------
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> Path | None:
    """
    Estrae il contenuto di un file .p7m (CAdES/CMS) usando openssl cms.
    - p7m_file_path: Path al file .p7m da estrarre
    - output_dir: Path alla directory dove salvare il file estratto (payload)
    Ritorna il Path del payload estratto, oppure None se c'è un errore.
    """
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
        st.error(f"Errore durante l’estrazione di «{p7m_file_path.name}»: {result.stderr.decode().strip()}")
        return None

    return output_file

# --- Funzione ricorsiva per estrarre ZIP/TAR “a matrioška” -----------------
def recursive_unpack(directory: Path):
    """
    Cerca ricorsivamente all’interno di 'directory' tutti i file .zip o .tar*,
    e li estrae in una sottocartella con lo stesso nome del file (senza estensione),
    quindi elimina l’archivio originale e ripete finché non rimangono più archivi.
    """
    for archive_path in directory.rglob("*"):
        if not archive_path.is_file():
            continue

        # ZIP
        if zipfile.is_zipfile(archive_path):
            try:
                extract_folder = archive_path.parent / archive_path.stem
                extract_folder.mkdir(exist_ok=True)
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(extract_folder)
                archive_path.unlink()
                # Dopo aver estratto questo archive, riparto da capo sulla cartella principale
                return recursive_unpack(directory)
            except zipfile.BadZipFile:
                # Se non è un zip valido, lo ignoro
                continue

        # TAR (tar, tar.gz, tar.bz2, tar.xz, ecc.)
        try:
            if tarfile.is_tarfile(archive_path):
                extract_folder = archive_path.parent / archive_path.stem
                extract_folder.mkdir(exist_ok=True)
                with tarfile.open(archive_path, "r:*") as tf:
                    tf.extractall(extract_folder)
                archive_path.unlink()
                return recursive_unpack(directory)
        except tarfile.TarError:
            continue

    # Se non ha trovato più archivi, esce
    return

# --- Pulsante di upload (senza filtro “type”, controlliamo in codice) ------
uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o un file .zip contenente .p7m",
    accept_multiple_files=True
)

if uploaded_files:
    # Cartella temporanea principale in cui mettere tutte le estrazioni
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded_file in uploaded_files:
        filename = uploaded_file.name
        suffix = Path(filename).suffix.lower()

        if suffix == ".zip":
            st.write(f"🔄 Rilevato file ZIP: {filename}")

            # 1) Salvo lo ZIP caricato su disco
            zip_temp_dir = Path(tempfile.mkdtemp(prefix="zip_unpack_"))
            zip_path = zip_temp_dir / filename
            with open(zip_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            # 2) Estraggo lo ZIP in zip_temp_dir
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(zip_temp_dir)
            except zipfile.BadZipFile:
                st.error(f"Errore: «{filename}» non è un archivio ZIP valido.")
                shutil.rmtree(zip_temp_dir, ignore_errors=True)
                continue

            # 3) Per ogni .p7m trovato dentro lo ZIP, lancio il processo di estrazione
            for p7m_path in zip_temp_dir.rglob("*.p7m"):
                stem = p7m_path.stem
                st.write(f"· Trovato .p7m dentro ZIP: {p7m_path.name}")

                # Creo la cartella dedicata per questo .p7m dentro root_temp
                file_dir = root_temp / stem
                file_dir.mkdir(parents=True, exist_ok=True)

                # Copio il .p7m nella sua cartella
                p7m_copy_path = file_dir / p7m_path.name
                shutil.copy2(p7m_path, p7m_copy_path)

                # Creo il subfolder "estratto"
                extracted_dir = file_dir / "estratto"
                extracted_dir.mkdir(exist_ok=True)

                # Estraggo il payload firmato
                payload_path = extract_signed_content(p7m_copy_path, extracted_dir)
                if not payload_path:
                    continue

                # Estraggo eventuali archivi annidati (ricorsivamente)
                recursive_unpack(extracted_dir)

            # 4) Pulisco la cartella temporanea dello ZIP
            shutil.rmtree(zip_temp_dir, ignore_errors=True)

        elif suffix == ".p7m":
            st.write(f"🔄 Rilevato file .p7m: {filename}")
            stem = Path(filename).stem

            # Creo la cartella dedicata per questo .p7m dentro root_temp
            file_dir = root_temp / stem
            file_dir.mkdir(parents=True, exist_ok=True)

            # Salvo il .p7m su disco
            p7m_file_path = file_dir / filename
            with open(p7m_file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            # Creo il subfolder "estratto"
            extracted_dir = file_dir / "estratto"
            extracted_dir.mkdir(exist_ok=True)

            # Estraggo il payload firmato
            payload_path = extract_signed_content(p7m_file_path, extracted_dir)
            if not payload_path:
                continue

            # Estraggo eventuali archivi annidati (ricorsivamente)
            recursive_unpack(extracted_dir)

        else:
            st.warning(f"Ignoro «{filename}»: estensione non supportata ({suffix}).")

    # --- A questo punto root_temp contiene tutte le cartelle per ogni .p7m (o p7m dentro ZIP) ---
    # Creiamo il file ZIP aggregato, mantenendo la struttura relativa a root_temp
    zip_file_path = root_temp / "all_extracted.zip"
    with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(root_temp):
            for file in files:
                if file == "all_extracted.zip":
                    continue
                file_path = Path(root) / file
                # Qui usiamo relative_to(root_temp) per mantenere esattamente la struttura
                rel_path = file_path.relative_to(root_temp)
                zipf.write(file_path, rel_path)

    # Pulsante per scaricare il .zip finale
    with open(zip_file_path, "rb") as f:
        st.download_button(
            label="Scarica un unico zip con tutte le cartelle estratte",
            data=f,
            file_name=zip_file_path.name,
            mime="application/zip"
        )
