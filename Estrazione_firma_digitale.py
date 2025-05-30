import streamlit as st
import os
import zipfile
import subprocess
from pathlib import Path

def extract_signed_content(p7m_file_path, output_dir):
    # Usa OpenSSL per estrarre il contenuto del file .p7m
    result = subprocess.run(
        ['openssl', 'smime', '-verify', '-in', str(p7m_file_path), '-noverify', '-out', str(output_dir / "estratto")],
        capture_output=True
    )
    if result.returncode != 0:
        st.error(f"Errore durante l'estrazione del file {p7m_file_path.name}: {result.stderr.decode()}")
        return False
    return True

st.title("Estrattore di file firmati digitalmente (CAdES)")

uploaded_files = st.file_uploader("Carica uno o più file .p7m", accept_multiple_files=True, type=["p7m"])

if uploaded_files:
    for uploaded_file in uploaded_files:
        st.write(f"File caricato: {uploaded_file.name}")
        
        # Crea una directory temporanea per ogni file
        temp_dir = Path(f"temp_{uploaded_file.name.replace('.p7m', '')}")
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Salva il file .p7m
        p7m_file_path = temp_dir / uploaded_file.name
        with open(p7m_file_path, 'wb') as f:
            f.write(uploaded_file.getbuffer())
        
        # Crea sottocartella per contenuto estratto
        extracted_dir = temp_dir / "estratto"
        extracted_dir.mkdir(exist_ok=True)

        # Estrai il contenuto
        if extract_signed_content(p7m_file_path, extracted_dir):
            # Crea archivio zip
            zip_file_path = temp_dir / f"{uploaded_file.name.replace('.p7m', '')}.zip"
            with zipfile.ZipFile(zip_file_path, 'w') as zipf:
                for root, _, files in os.walk(extracted_dir):
                    for file in files:
                        file_path = Path(root) / file
                        zipf.write(file_path, file_path.relative_to(extracted_dir))

            # Offri il download
            with open(zip_file_path, 'rb') as f:
                st.download_button(
                    label="Scarica il file estratto",
                    data=f,
                    file_name=zip_file_path.name
                )
