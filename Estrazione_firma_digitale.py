import streamlit as st
from pathlib import Path
import tempfile, shutil, zipfile, tarfile, subprocess
from datetime import datetime
import re
from PIL import Image

# --- Layout con logo a destra ---------------------------------------------
col1, col2 = st.columns([8, 1])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")  # Percorso relativo nella repo
    st.image(logo, width=120)
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path | None, str, bool]:
    payload_filename = p7m_file_path.stem
    output_file = output_dir / payload_filename

    # 1) estraggo il payload firmato
    res = subprocess.run(
        ["openssl", "cms", "-verify", "-in", str(p7m_file_path),
         "-inform", "DER", "-noverify", "-out", str(output_file)],
        capture_output=True
    )
    if res.returncode != 0:
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {res.stderr.decode().strip()}")
        return None, "", False

    # 2) estraggo il/i certificato/i in formato PEM
    cert_pem_path = output_dir / (payload_filename + "_cert.pem")
    proc_cert = subprocess.run(
        ["openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_file_path),
         "-print_certs", "-out", str(cert_pem_path)],
        capture_output=True
    )
    if proc_cert.returncode != 0:
        st.error(f"Errore estrazione cert da «{p7m_file_path.name}»: {proc_cert.stderr.decode().strip()}")
        return output_file, "Sconosciuto", False

    # 3) leggo subject e dates
    proc_info = subprocess.run(
        ["openssl", "x509", "-in", str(cert_pem_path), "-noout", "-subject", "-dates"],
        capture_output=True, text=True
    )
    if proc_info.returncode != 0:
        st.error(f"Errore lettura info cert da «{cert_pem_path.name}»: {proc_info.stderr.strip()}")
        return output_file, "Sconosciuto", False

    lines = proc_info.stdout.splitlines()
    # riga 0: subject= /C=IT/O=…/CN=Mario Rossi
    # riga 1: notBefore=Jun  1 00:00:00 2023 GMT
    # riga 2: notAfter=May 31 23:59:59 2025 GMT
    subject_line = lines[0]
    m = re.search(r"CN=([^,/]+)", subject_line)
    signer_name = m.group(1).strip() if m else "Sconosciuto"

    def parse_openssl_date(s: str) -> datetime:
        return datetime.strptime(s.strip() + " UTC", "%b %d %H:%M:%S %Y %Z")

    not_before = parse_openssl_date(lines[1].split("=", 1)[1])
    not_after  = parse_openssl_date(lines[2].split("=", 1)[1])
    now = datetime.utcnow()
    is_valid = (not_before <= now <= not_after)

    return output_file, signer_name, is_valid

def recursive_unpack(directory: Path):
    # [La tua funzione così com’è, senza modifiche]
    for archive_path in directory.rglob("*"):
        if not archive_path.is_file():
            continue
        if zipfile.is_zipfile(archive_path):
            try:
                extract_folder = archive_path.parent / archive_path.stem
                extract_folder.mkdir(exist_ok=True)
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(extract_folder)
                archive_path.unlink()
                return recursive_unpack(directory)
            except zipfile.BadZipFile:
                continue
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
    return

# --- Input nome ZIP uscita come prima ---
output_name = st.text_input(
    "Nome del file ZIP di output (includi “.zip” o sarà aggiunto automaticamente):",
    value="all_extracted.zip"
)
if output_name.strip().lower().endswith(".zip"):
    output_filename = output_name.strip()
else:
    output_filename = output_name.strip() + ".zip"

uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o archiv i .zip contenenti .p7m",
    accept_multiple_files=True
)

if uploaded_files:
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded_file in uploaded_files:
        filename = uploaded_file.name
        suffix = Path(filename).suffix.lower()

        if suffix == ".zip":
            st.write(f"🔄 Rilevato file ZIP: {filename}")
            zip_input_stem = Path(filename).stem
            zip_folder = root_temp / zip_input_stem
            zip_folder.mkdir(parents=True, exist_ok=True)

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

            for p7m_path in zip_temp_dir.rglob("*.p7m"):
                rel_dir = p7m_path.parent.relative_to(zip_temp_dir)
                st.write(f"· Trovato .p7m dentro ZIP «{filename}» in **{rel_dir}**: {p7m_path.name}")

                target_folder = zip_folder / rel_dir
                target_folder.mkdir(parents=True, exist_ok=True)

                p7m_copy_path = target_folder / p7m_path.name
                shutil.copy2(p7m_path, p7m_copy_path)

                # CHIAMO LA NUOVA FUNZIONE
                payload_path, signer_name, firma_ok = extract_signed_content(p7m_copy_path, target_folder)
                if not payload_path:
                    continue

                p7m_copy_path.unlink()
                recursive_unpack(target_folder)

                # MOSTRO NOME FIRMATARIO E STATO
                colx, coly = st.columns([4, 1])
                with colx:
                    st.write(f"  – File estratto: **{payload_path.name}**")
                    st.write(f"    Firmato da: **{signer_name}**")
                with coly:
                    if firma_ok:
                        st.success("Firma valida ✅")
                    else:
                        st.error("Firma NON valida ⚠️")

            shutil.rmtree(zip_temp_dir, ignore_errors=True)

        elif suffix == ".p7m":
            st.write(f"🔄 Rilevato file .p7m: {filename}")
            p7m_stem = Path(filename).stem
            file_folder = root_temp / p7m_stem
            file_folder.mkdir(parents=True, exist_ok=True)

            p7m_file_path = file_folder / filename
            with open(p7m_file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            payload_path, signer_name, firma_ok = extract_signed_content(p7m_file_path, file_folder)
            if not payload_path:
                continue

            p7m_file_path.unlink()
            recursive_unpack(file_folder)

            # MOSTRO NOME FIRMATARIO E STATO
            colx, coly = st.columns([4, 1])
            with colx:
                st.write(f"  – File estratto: **{payload_path.name}**")
                st.write(f"    Firmato da: **{signer_name}**")
            with coly:
                if firma_ok:
                    st.success("Firma valida ✅")
                else:
                    st.error("Firma NON valida ⚠️")

        else:
            st.warning(f"Ignoro «{filename}»: estensione non supportata ({suffix}).")

    # Costruzione dello ZIP finale
    zip_file_path = root_temp / output_filename
    with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(root_temp):
            for file in files:
                if file == output_filename:
                    continue
                file_path = Path(root) / file
                rel_path = file_path.relative_to(root_temp)
                zipf.write(file_path, rel_path)

    with open(zip_file_path, "rb") as f:
        st.download_button(
            label="Scarica il file ZIP con tutte le estrazioni",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
