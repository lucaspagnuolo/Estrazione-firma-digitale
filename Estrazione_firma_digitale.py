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
col1, col2 = st.columns([8, 1])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")  # Percorso relativo nella repo
    st.image(logo, width=120)

# --- Funzione che esegue il cms -verify di OpenSSL e legge certificato -----
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path | None, str, bool]:
    """
    Estrae il contenuto di un file .p7m, estrae il certificato, ne legge i dati e ritorna:
    (output_file, signer_name, is_valid).
    Se c'è un errore nell’estrazione, restituisce (None, "", False).
    Il .pem viene subito rimosso, per non lasciare tracce.
    """

    payload_filename = p7m_file_path.stem
    output_file = output_dir / payload_filename

    # 1) Estraggo il payload firmato
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
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {result.stderr.decode().strip()}")
        return None, "", False

    # 2) Estraggo il/i certificato/i in formato PEM
    cert_pem_path = output_dir / (payload_filename + "_cert.pem")
    proc_cert = subprocess.run(
        [
            "openssl", "pkcs7",
            "-inform", "DER",
            "-in", str(p7m_file_path),
            "-print_certs",
            "-out", str(cert_pem_path)
        ],
        capture_output=True
    )
    if proc_cert.returncode != 0:
        st.error(f"Errore estrazione certificato da «{p7m_file_path.name}»: {proc_cert.stderr.decode().strip()}")
        return output_file, "Sconosciuto", False

    # 3) Leggo subject e date di validità
    proc_info = subprocess.run(
        [
            "openssl", "x509",
            "-in", str(cert_pem_path),
            "-noout",
            "-subject",
            "-dates"
        ],
        capture_output=True,
        text=True
    )
    if proc_info.returncode != 0:
        st.error(f"Errore lettura info certificato da «{cert_pem_path.name}»: {proc_info.stderr.strip()}")
        # Rimuovo comunque il file .pem, anche in caso di errore
        try:
            cert_pem_path.unlink()
        except:
            pass
        return output_file, "Sconosciuto", False

    # Elimino subito il .pem, non serve tenerlo
    try:
        cert_pem_path.unlink()
    except:
        pass

    lines = proc_info.stdout.splitlines()
    # st.write("DEBUG: subject grezzo:", repr(lines[0]))  # puoi de-commentare in caso di debug

    # 3a) Estraggo il firmatario cercando più RDN possibili
    subject_line = lines[0]
    candidato_rdn = ["CN", "SN", "UID", "emailAddress", "SERIALNUMBER"]
    signer_name = "Sconosciuto"
    for rdn in candidato_rdn:
        pattern = rf"{rdn}\s*=\s*([^,/]+)"
        m = re.search(pattern, subject_line)
        if m:
            signer_name = m.group(1).strip()
            break

    # 3b) Converto le date (notBefore / notAfter) in datetime
    def parse_openssl_date(s: str) -> datetime:
        text = s.strip()  # es. "Jun  1 00:00:00 2023 GMT"
        return datetime.strptime(text, "%b %d %H:%M:%S %Y %Z")

    not_before = parse_openssl_date(lines[1].split("=", 1)[1])
    not_after  = parse_openssl_date(lines[2].split("=", 1)[1])

    now = datetime.utcnow()
    is_valid = (not_before <= now <= not_after)

    return output_file, signer_name, is_valid

# --- Funzione ricorsiva per estrarre solo ZIP “a matrioska” -----------------
def recursive_unpack(directory: Path):
    """
    Cerca ricorsivamente all’interno di 'directory' tutti i file .zip,
    li estrae in una sottocartella con lo stesso nome del file (senza estensione),
    elimina l’archivio originale e ripete finché non rimangono più archivi.
    """
    for archive_path in directory.rglob("*.zip"):
        if not archive_path.is_file():
            continue

        try:
            extract_folder = archive_path.parent / archive_path.stem

            # Se esiste un file con lo stesso nome, lo rimuovo
            if extract_folder.exists() and extract_folder.is_file():
                extract_folder.unlink()

            # Creo la cartella (se esiste come directory, esist_ok=True la ignora senza errore)
            extract_folder.mkdir(exist_ok=True)

            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(extract_folder)

            archive_path.unlink()
            # Ricorsione su cartella appena estratta
            recursive_unpack(extract_folder)

        except Exception as e:
            st.warning(f"Errore estraendo {archive_path.name}: {e}")

# --- Input per il nome del file ZIP di output --------------------------------
output_name = st.text_input(
    "Nome del file ZIP di output (includi “.zip” o sarà aggiunto automaticamente):",
    value="all_extracted.zip"
)
# Se l'utente non ha inserito ".zip" alla fine, lo aggiungiamo:
if output_name.strip().lower().endswith(".zip"):
    output_filename = output_name.strip()
else:
    output_filename = output_name.strip() + ".zip"

# --- Pulsante di upload (senza filtro “type”, controlliamo in codice) -------
uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o archivi .zip contenenti .p7m",
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
            # Creo una cartella dedicata (per evitare clash di nomi) solo per l'estrazione iniziale
            zip_temp_dir = Path(tempfile.mkdtemp(prefix="zip_unpack_"))
            zip_path = zip_temp_dir / filename
            with open(zip_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            # 1) Estraggo lo ZIP caricato in zip_temp_dir
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(zip_temp_dir)
            except zipfile.BadZipFile:
                st.error(f"Errore: «{filename}» non è un archivio ZIP valido.")
                shutil.rmtree(zip_temp_dir, ignore_errors=True)
                continue

            # 2) Scompatta eventuali ZIP annidati all’interno del primo ZIP
            recursive_unpack(zip_temp_dir)

            # 3) A questo punto, cerco tutti i .p7m in zip_temp_dir (qualsiasi livello)
            for p7m_path in zip_temp_dir.rglob("*.p7m"):
                # Percorso relativo rispetto alla radice dello ZIP (per mantenere struttura parziale)
                rel_dir = p7m_path.parent.relative_to(zip_temp_dir)
                st.write(f"· Trovato .p7m dentro ZIP «{filename}» in **{rel_dir}**: {p7m_path.name}")

                # Creo la stessa sottocartella all'interno di root_temp
                target_folder = root_temp / zip_path.stem / rel_dir
                target_folder.mkdir(parents=True, exist_ok=True)

                # Copio il .p7m in quella cartella
                p7m_copy_path = target_folder / p7m_path.name
                shutil.copy2(p7m_path, p7m_copy_path)

                # 4) Estraggo payload, certificato e verifico firmatario
                payload_path, signer_name, firma_ok = extract_signed_content(p7m_copy_path, target_folder)
                if not payload_path:
                    # Se c'è stato errore, passo avanti
                    continue

                # Rimuovo il file .p7m originale (per lasciare solo il documento estratto)
                p7m_copy_path.unlink()

                # 5) Estrazione di eventuali ZIP presenti nel payload appena estratto
                recursive_unpack(target_folder)

                # 6) Mostro in UI il nome del firmatario e stato firma
                colx, coly = st.columns([4, 1])
                with colx:
                    st.write(f"  – File estratto: **{payload_path.name}**")
                    st.write(f"    Firmato da: **{signer_name}**")
                with coly:
                    if firma_ok:
                        st.success("Firma valida ✅")
                    else:
                        st.error("Firma NON valida ⚠️")

            # 7) Pulisco la cartella temporanea dello ZIP
            shutil.rmtree(zip_temp_dir, ignore_errors=True)

        elif suffix == ".p7m":
            st.write(f"🔄 Rilevato file .p7m: {filename}")

            # 1) Creo una cartella temporanea per salvare e processare il .p7m
            temp_single = Path(tempfile.mkdtemp(prefix="single_p7m_"))
            p7m_file_path = temp_single / filename
            with open(p7m_file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            # 2) Estraggo payload, certificato e verifico firmatario, ma metto l'output direttamente in root_temp
            payload_path, signer_name, firma_ok = extract_signed_content(p7m_file_path, root_temp)
            if not payload_path:
                shutil.rmtree(temp_single, ignore_errors=True)
                continue

            # 3) Rimuovo il file .p7m originale dal temp locale
            try:
                p7m_file_path.unlink()
            except:
                pass

            # 4) Estrazione di eventuali ZIP presenti nel payload appena estratto
            recursive_unpack(root_temp)

            # 5) Mostro in UI il nome del firmatario e stato firma
            colx, coly = st.columns([4, 1])
            with colx:
                st.write(f"  – File estratto: **{payload_path.name}**")
                st.write(f"    Firmato da: **{signer_name}**")
            with coly:
                if firma_ok:
                    st.success("Firma valida ✅")
                else:
                    st.error("Firma NON valida ⚠️")

            # 6) Rimuovo la cartella temporanea
            shutil.rmtree(temp_single, ignore_errors=True)

        else:
            st.warning(f"Ignoro «{filename}»: estensione non supportata ({suffix}).")

    # --- Costruzione dello ZIP finale mantenendo la struttura su root_temp ------
    zip_file_path = root_temp / output_filename
    with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(root_temp):
            for file in files:
                # Evitiamo di includere il file ZIP di output all’interno di sé stesso
                if file == output_filename:
                    continue
                file_path = Path(root) / file
                rel_path = file_path.relative_to(root_temp)
                zipf.write(file_path, rel_path)

    # Pulsante per scaricare il .zip finale con nome personalizzato
    with open(zip_file_path, "rb") as f:
        st.download_button(
            label="Scarica il file ZIP con tutte le estrazioni",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
