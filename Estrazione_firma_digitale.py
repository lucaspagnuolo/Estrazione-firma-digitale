import streamlit as st
import os
import zipfile
import tarfile
import subprocess
import tempfile
from pathlib import Path

def extract_signed_content(p7m_file_path, output_dir):
    """
    Estrae il contenuto di un file .p7m (CAdES/CMS) usando openssl cms.
    Se il payload estratto è un archivio (ZIP o TAR), non lo scompatta qui: 
    questa funzione si limita a scrivere il payload grezzo in 'output_dir'.
    - p7m_file_path: Path al file .p7m da estrarre
    - output_dir: Path alla directory dove salvare il file estratto (payload)
    Ritorna il Path del file estratto (payload), oppure None in caso di errore.
    """
    payload_filename = p7m_file_path.stem  # es. "documenti_multiple.zip"
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

def unpack_inner_archive(payload_path, destination_dir):
    """
    Se 'payload_path' è un archivio ZIP o TAR, lo scompatta dentro 'destination_dir'.
    Ritorna True se è stato un archivio e l'abbiamo scompattato, False altrimenti.
    Dopo lo scompattamento, elimina l'archivio originale.
    """
    # Caso ZIP
    if zipfile.is_zipfile(payload_path):
        with zipfile.ZipFile(payload_path, 'r') as zf:
            zf.extractall(destination_dir)
        payload_path.unlink()  # cancello l'archivio ZIP originale
        return True

    # Caso TAR / TAR.GZ / TAR.BZ2
    try:
        if tarfile.is_tarfile(payload_path):
            with tarfile.open(payload_path, 'r:*') as tf:
                tf.extractall(destination_dir)
            payload_path.unlink()  # cancello l'archivio TAR originale
            return True
    except tarfile.TarError:
        pass

    return False

st.title("Estrattore di file firmati digitalmente (CAdES)")

uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m",
    accept_multiple_files=True,
    type=["p7m"]
)

if uploaded_files:
    # Creo una cartella temporanea unica per tutti i file caricati
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))
    
    for uploaded_file in uploaded_files:
        st.write(f"File caricato: {uploaded_file.name}")
        
        # Crea una sottocartella per questo .p7m, usando il nome senza estensione
        stem = Path(uploaded_file.name).stem
        file_dir = root_temp / stem
        file_dir.mkdir(parents=True, exist_ok=True)
        
        # Salva il file .p7m
        p7m_file_path = file_dir / uploaded_file.name
        with open(p7m_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Cartella dove mettere l'output dell'estrazione
        extracted_dir = file_dir / "estratto"
        extracted_dir.mkdir(exist_ok=True)

        # Estraggo il payload firmato
        payload_path = extract_signed_content(p7m_file_path, extracted_dir)
        if not payload_path:
            continue

        # Se il payload è un archivio, lo scompatta
        _ = unpack_inner_archive(payload_path, extracted_dir)

    # Dopo aver estratto tutti, creo un unico ZIP con tutte le cartelle
    zip_file_path = root_temp / "all_extracted.zip"
    with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(root_temp):
            for file in files:
                # Evito di includere lo stesso ZIP all'interno
                if file == "all_extracted.zip":
                    continue
                file_path = Path(root) / file
                zipf.write(file_path, file_path.relative_to(root_temp))

    # Mostro un unico pulsante per scaricare lo ZIP con tutto il contenuto
    with open(zip_file_path, "rb") as f:
        st.download_button(
            label="Scarica un unico zip con tutte le cartelle estratte",
            data=f,
            file_name=zip_file_path.name,
            mime="application/zip"
        )
