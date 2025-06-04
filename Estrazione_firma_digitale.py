import streamlit as st
import os
import zipfile
import tarfile
import subprocess
import tempfile
import base64
from pathlib import Path

# Layout con logo a destra
col1, col2 = st.columns([8, 1])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")  # Percorso relativo nella repo
    st.image(logo, width=120)
def get_image_base64(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode()

def extract_signed_content(p7m_file_path, output_dir):
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

def unpack_inner_archive(payload_path, destination_dir):
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

# === TITOLO E LOGO ===
st.set_page_config(layout="wide")  # Opzionale: per più spazio

st.title("Estrattore di file firmati digitalmente (CAdES)")

# Inserisce il logo in alto a destra
logo_path = Path(r"C:\Users\luca.spagnuolo.ext\Downloads\Consip_Logo.png")
if logo_path.exists():
    logo_base64 = get_image_base64(logo_path)
    st.markdown(
        f"""
        <div style="position: absolute; top: 10px; right: 10px;">
            <img src="data:image/png;base64,{logo_base64}" width="120"/>
        </div>
        """,
        unsafe_allow_html=True
    )

# === UPLOADER ===
uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m",
    accept_multiple_files=True,
    type=["p7m"]
)

if uploaded_files:
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded_file in uploaded_files:
        st.write(f"File caricato: {uploaded_file.name}")
        
        stem = Path(uploaded_file.name).stem
        file_dir = root_temp / stem
        file_dir.mkdir(parents=True, exist_ok=True)
        
        p7m_file_path = file_dir / uploaded_file.name
        with open(p7m_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        extracted_dir = file_dir / "estratto"
        extracted_dir.mkdir(exist_ok=True)

        payload_path = extract_signed_content(p7m_file_path, extracted_dir)
        if not payload_path:
            continue

        _ = unpack_inner_archive(payload_path, extracted_dir)

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
            label="Scarica un unico zip con tutte le cartelle estratte",
            data=f,
            file_name=zip_file_path.name,
            mime="application/zip"
        )
