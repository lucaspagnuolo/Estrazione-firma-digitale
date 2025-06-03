import streamlit as st
import os
import zipfile
import subprocess
from pathlib import Path

def extract_signed_content(p7m_file_path, output_dir):
    """
    Estrae il contenuto di un file .p7m (CAdES/CMS) usando openssl cms.
    - p7m_file_path: Path al file .p7m da estrarre
    - output_dir: Path alla directory dove salvare il file estratto
    """
    # Costruisco il percorso di output: estraggo il nome senza .p7m
    output_file = output_dir / p7m_file_path.stem

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
        return False

    return True

st.title("Estrattore di file firmati digitalmente (CAdES)")

# Uploader per file .p7m
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
        
        # Creo la sottocartella dove metterò il file estratto
        extracted_dir = temp_dir / "estratto"
        extracted_dir.mkdir(exist_ok=True)

        # Estraggo il contenuto firmato
        if extract_signed_content(p7m_file_path, extracted_dir):
            # Creo uno ZIP contenente tutto ciò che sta in extracted_dir
            zip_file_path = temp_dir / f"{uploaded_file.name.replace('.p7m', '')}.zip"
            with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(extracted_dir):
                    for file in files:
                        file_path = Path(root) / file
                        # Aggiungo il file allo ZIP, mantenendo la struttura relativa a extracted_dir
                        zipf.write(file_path, file_path.relative_to(extracted_dir))

            # Mostro il pulsante di download
            with open(zip_file_path, "rb") as f:
                st.download_button(
                    label="Scarica lo zip con il contenuto estratto",
                    data=f,
                    file_name=zip_file_path.name,
                    mime="application/zip"
                )
