import streamlit as st
import os
import zipfile
import tarfile
import subprocess
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
    # Costruisco il percorso di output: rimuovo l'estensione .p7m
    payload_filename = p7m_file_path.stem  # es. "documenti_multiple.zip"
    output_file = output_dir / payload_filename

    # Eseguo il comando openssl cms -verify (formato DER)
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

# Uploader per i file .p7m
uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m",
    accept_multiple_files=True,
    type=["p7m"]
)

if uploaded_files:
    for uploaded_file in uploaded_files:
        st.write(f"File caricato: {uploaded_file.name}")
        
        # Creo una directory temporanea dedicata a questo file
        temp_dir = Path(f"temp_{uploaded_file.name.replace('.p7m', '')}")
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Salvo il file .p7m all'interno della cartella temporanea
        p7m_file_path = temp_dir / uploaded_file.name
        with open(p7m_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Creo la sottocartella dove metterò il payload estratto
        extracted_dir = temp_dir / "estratto"
        extracted_dir.mkdir(exist_ok=True)

        # Estraggo il payload firmato (potrebbe essere un singolo file .pdf, .zip, .tar, ecc.)
        payload_path = extract_signed_content(p7m_file_path, extracted_dir)
        if not payload_path:
            # Se l'estrazione è fallita, passo al prossimo file
            continue

        # Se il payload è un archivio (ZIP o TAR), lo scompatto nella stessa cartella 'estratto'
        # e rimuovo l'archivio originale.
        _ = unpack_inner_archive(payload_path, extracted_dir)

        # A questo punto, 'extracted_dir' contiene TUTTI i file estratti:
        # - Se il p7m conteneva un singolo PDF, 'extracted_dir' conterrà quel PDF
        # - Se il p7m conteneva un .zip con 500 documenti, 'extracted_dir' conterrà i 500 documenti

        # Creo uno ZIP di tutto ciò che si trova in 'extracted_dir'
        zip_file_path = temp_dir / f"{uploaded_file.name.replace('.p7m', '')}.zip"
        with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(extracted_dir):
                for file in files:
                    file_path = Path(root) / file
                    zipf.write(file_path, file_path.relative_to(extracted_dir))

        # Infine mostro il pulsante di download per l'utente
        with open(zip_file_path, "rb") as f:
            st.download_button(
                label="Scarica lo zip con il contenuto estratto",
                data=f,
                file_name=zip_file_path.name,
                mime="application/zip"
            )
