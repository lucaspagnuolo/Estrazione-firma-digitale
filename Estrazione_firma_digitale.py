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
col1, col2 = st.columns([7, 3])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# --- Funzione che esegue “openssl cms -verify” e legge il certificato -----
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path | None, str, bool]:
    """
    Estrae il payload di un .p7m, estrae il certificato (rimuovendo subito il .pem),
    e ritorna (output_file, signer_name, is_valid). Se il payload risultante
    è un vero ZIP (verificandone gli header), lo rinomina aggiungendo “.zip”.
    """
    payload_basename = p7m_file_path.stem
    output_file = output_dir / payload_basename

    # 1) Estraggo il payload (file “grezzo”) con openssl cms -verify
    cmd1 = [
        "openssl", "cms", "-verify",
        "-in", str(p7m_file_path),
        "-inform", "DER",
        "-noverify",
        "-out", str(output_file)
    ]
    res1 = subprocess.run(cmd1, capture_output=True)
    if res1.returncode != 0:
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {res1.stderr.decode().strip()}")
        return None, "", False

    # 2) Estraggo il certificato in PEM, leggo subject/dates, poi elimino il .pem
    cert_pem_path = output_dir / (payload_basename + "_cert.pem")
    cmd2 = [
        "openssl", "pkcs7",
        "-inform", "DER",
        "-in", str(p7m_file_path),
        "-print_certs",
        "-out", str(cert_pem_path)
    ]
    res2 = subprocess.run(cmd2, capture_output=True)
    if res2.returncode != 0:
        st.error(f"Errore estrazione certificato da «{p7m_file_path.name}»: {res2.stderr.decode().strip()}")
        return output_file, "Sconosciuto", False

    cmd3 = [
        "openssl", "x509",
        "-in", str(cert_pem_path),
        "-noout",
        "-subject",
        "-dates"
    ]
    res3 = subprocess.run(cmd3, capture_output=True, text=True)
    if res3.returncode != 0:
        st.error(f"Errore lettura info certificato da «{cert_pem_path.name}»: {res3.stderr.strip()}")
        # anche in caso di errore, elimino il .pem
        try:
            cert_pem_path.unlink()
        except:
            pass
        return output_file, "Sconosciuto", False

    # Elimino il .pem, non serve conservarlo
    try:
        cert_pem_path.unlink()
    except:
        pass

    # Estraggo subject e controllo validità
    lines = res3.stdout.splitlines()
    subject_line = lines[0]
    candidato_rdn = ["CN", "SN", "UID", "emailAddress", "SERIALNUMBER"]
    signer_name = "Sconosciuto"
    for rdn in candidato_rdn:
        m = re.search(rf"{rdn}\s*=\s*([^,/]+)", subject_line)
        if m:
            signer_name = m.group(1).strip()
            break

    def parse_openssl_date(s: str) -> datetime:
        return datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z")

    not_before = parse_openssl_date(lines[1].split("=", 1)[1])
    not_after  = parse_openssl_date(lines[2].split("=", 1)[1])
    now = datetime.utcnow()
    is_valid = (not_before <= now <= not_after)

    # 3) Se il payload “output_file” è un vero ZIP (verifico gli header),
    #    lo rinomino aggiungendo l’estensione .zip.
    try:
        with open(output_file, "rb") as f:
            header = f.read(4)
        if header.startswith(b"PK\x03\x04"):
            new_zip = output_file.with_suffix(".zip")
            output_file.rename(new_zip)
            output_file = new_zip
    except:
        pass

    return output_file, signer_name, is_valid

# --- Funzione ricorsiva che scompatta tutti gli ZIP e appiattisce cartelle ---
def recursive_unpack_and_flatten(directory: Path):
    """
    Per ogni file “*.zip” in modo ricorsivo sotto directory, estrae
    in una cartella con lo stesso nome del file (senza estensione),
    poi:
      - se quella cartella contiene esattamente UNA sottocartella senza altri file,
        appiattisce il contenuto (sposta le sottocartelle nella cartella padre),
        eliminando quindi un livello di directory.
      - elimina l’archivio .zip di partenza.
    Ripete finché non rimangano più *.zip in ogni livello.
    """
    for archive_path in list(directory.rglob("*.zip")):
        if not archive_path.is_file():
            continue

        parent_folder = archive_path.parent
        extract_folder = parent_folder / f"{archive_path.stem}_unzipped"

        # Se esiste un file con lo stesso nome, lo elimino
        if extract_folder.exists() and extract_folder.is_file():
            extract_folder.unlink()

        # Creo la directory di estrazione
        extract_folder.mkdir(exist_ok=True)

        # Estraggo i contenuti
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(extract_folder)
        except zipfile.BadZipFile:
            st.warning(f"Attenzione: «{archive_path.name}» non è un archivio ZIP valido.")
            archive_path.unlink(missing_ok=True)
            continue

        # Rimuovo il .zip originale
        archive_path.unlink(missing_ok=True)

        # Flatten automatico: se dentro extract_folder c’è UNA sola sottocartella
        # e nessun file a fianco, sposto tutto verso l’alto e cancello quella subdir
        items = list(extract_folder.iterdir())
        if len(items) == 1 and items[0].is_dir():
            lone_sub = items[0]
            for sub_item in lone_sub.iterdir():
                shutil.move(str(sub_item), str(extract_folder))
            lone_sub.rmdir()

        # Ricorsione
        recursive_unpack_and_flatten(extract_folder)

# --- Funzione per confrontare due cartelle e verificare se contengono gli stessi file ---
def compare_directories(dir1: Path, dir2: Path) -> bool:
    """
    Confronta due cartelle per verificare se contengono gli stessi file (per nome ed estensione).
    """
    files1 = sorted([f.name for f in dir1.iterdir() if f.is_file()])
    files2 = sorted([f.name for f in dir2.iterdir() if f.is_file()])
    return files1 == files2

# --- Funzione per rimuovere cartelle duplicate ---
def remove_duplicate_folders(root_dir: Path):
    """
    Scorre tutte le cartelle e, se trova una sottocartella con lo stesso nome e contenuto
    della cartella padre, la elimina.
    """
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for dirname in dirnames:
            parent_dir = Path(dirpath)
            child_dir = parent_dir / dirname
            if compare_directories(parent_dir, child_dir):
                shutil.rmtree(child_dir)

# --- Procedura principale: processa ogni directory cercando .p7m ----------
def process_directory_for_p7m(directory: Path, log_root: str):
    """
    Cerca in directory tutti i file “*.p7m” (a ogni livello) e, per ognuno:
      1) chiama extract_signed_content su quel file, mettendo il payload
         (pdf o zip) nella stessa cartella in cui si trovava il .p7m.
      2) elimina il .p7m originale.
      3) se il payload estratto era un .zip, lo scompatta con
         recursive_unpack_and_flatten() nella sua cartella e poi
         richiama ricorsivamente process_directory_for_p7m() dentro
         la sottocartella appena creata, in modo da processare eventuali
         .p7m ancora più in profondità.
      4) logga in UI chi ha firmato e lo stato di validità.
    """
    # Itero su una lista statica di .p7m (li cancellerò mano a mano)
    for p7m_path in list(directory.rglob("*.p7m")):
        rel = p7m_path.relative_to(directory)
        st.write(f"{log_root} · Trovato .p7m in **{rel.parent}**: {p7m_path.name}")

        payload_path, signer_name, firma_ok = extract_signed_content(p7m_path, p7m_path.parent)
        if not payload_path:
            continue

        # Rimuovo il .p7m
        try:
            p7m_path.unlink()
        except:
            pass

        # Se il payload estratto è un .zip, lo scompatto e rientro con ricorsione
        if payload_path.suffix.lower() == ".zip":
            recursive_unpack_and_flatten(payload_path.parent)

            # Provo a processare eventuali .p7m dentro la nuova cartella
            nuova_cartella = payload_path.parent / payload_path.stem
            if nuova_cartella.exists() and nuova_cartella.is_dir():
                process_directory_for_p7m(nuova_cartella, log_root + "  ")

            # Rimuovo l’eventuale archivio .zip residuo
            try:
                payload_path.unlink()
            except:
                pass

        # Log in UI
        colx, coly = st.columns([4, 1])
        with colx:
            st.write(f"  – File estratto: **{payload_path.stem + payload_path.suffix}**")
            st.write(f"    Firmato da: **{signer_name}**")
        with coly:
            if firma_ok:
                st.success("Firma valida ✅")
            else:
                st.error("Firma NON valida ⚠️")

# --- Funzione di “cleanup” per rimuovere directory con soli .p7m non processati ---
def cleanup_unprocessed_p7m_dirs(root_dir: Path):
    """
    Scorre ricorsivamente tutte le cartelle dentro root_dir.
    Se trova una cartella che contiene solo file .p7m (e nessun altro tipo di file
    o sottocartelle), elimina quei .p7m e rimuove la cartella.
    Questo evita di lasciare directory con soli .p7m non processati.
    """
    # Otteniamo tutte le directory ordinate dalla più profonda alla meno profonda
    all_dirs = sorted(
        (p for p in root_dir.rglob("*") if p.is_dir()),
        key=lambda d: len(str(d).split(os.sep)),
        reverse=True
    )
    for d in all_dirs:
        files = [f for f in d.iterdir() if f.is_file()]
        # Se ci sono file e tutti hanno estensione .p7m, li elimino e rimuovo la cartella
        if files and all(f.suffix.lower() == ".p7m" for f in files):
            for f in files:
                try:
                    f.unlink()
                except:
                    pass
            try:
                d.rmdir()
            except:
                pass

# --- Nuova funzione di “cleanup” per rimuovere cartelle che terminano con “zip” ---
# se esiste già la stessa cartella senza “zip” (evita doppioni)
def cleanup_extra_zip_named_dirs(root_dir: Path):
    """
    Scorre tutte le directory sotto root_dir. Se trova una directory
    il cui nome termina con “zip” e accanto esiste una directory con
    lo stesso nome senza quel suffisso, rimuove la cartella “zip”.
    """
    # Scorro le directory in ordine profondo→superficiale (in caso di annidamenti)
    all_dirs = sorted(
        (d for d in root_dir.rglob("*") if d.is_dir()),
        key=lambda d: len(str(d).split(os.sep)),
        reverse=True
    )
    for d in all_dirs:
        if d.name.lower().endswith("zip"):
            sibling_name = d.name[:-3]
            sibling = d.parent / sibling_name
            if sibling.exists() and sibling.is_dir():
                # Rimuovo completamente la cartella “d” (che terminava in “zip”)
                shutil.rmtree(d, ignore_errors=True)

# --- Streamlit: upload multiplo, creazione cartelle temporanee -------------
output_name = st.text_input(
    "Nome del file ZIP di output (includi “.zip” o sarà aggiunto automaticamente):",
    value="all_extracted.zip"
)
if output_name.strip().lower().endswith(".zip"):
    output_filename = output_name.strip()
else:
    output_filename = output_name.strip() + ".zip"

uploaded_files = st.file_uploader(
    "Carica uno o più file .p7m o archivi .zip contenenti .p7m",
    accept_multiple_files=True
)

if uploaded_files:
    # Cartella temporanea principale
    root_temp = Path(tempfile.mkdtemp(prefix="combined_"))

    for uploaded_file in uploaded_files:
        nome = uploaded_file.name
        suff = Path(nome).suffix.lower()

        if suff == ".zip":
            st.write(f"🔄 Rilevato file ZIP: {nome}")

            # 1) Creo cartella temporanea per decomprimere questo ZIP
            temp_zip_dir = Path(tempfile.mkdtemp(prefix="zip_unpack_"))
            zip_path = temp_zip_dir / nome
            with open(zip_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            # 2) Estraggo tutto dentro temp_zip_dir
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(temp_zip_dir)
            except zipfile.BadZipFile:
                st.error(f"Errore: «{nome}» non è un archivio ZIP valido.")
                shutil.rmtree(temp_zip_dir, ignore_errors=True)
                continue

            # 3) Se temp_zip_dir contiene una sola cartella principale, la uso; altrimenti, rimango su temp_zip_dir
            items = [p for p in temp_zip_dir.iterdir() if p != zip_path]
            if len(items) == 1 and items[0].is_dir():
                base_dir = items[0]
            else:
                base_dir = temp_zip_dir

            # 4) Scompattiamo tutti gli ZIP annidati ed appiattiamo le cartelle
            recursive_unpack_and_flatten(base_dir)

            # 5) Copio TUTTO (cartelle e file) da base_dir → root_temp/<nome_base_zip>/
            nome_base = zip_path.stem
            target_root_for_this_zip = root_temp / nome_base
            shutil.copytree(base_dir, target_root_for_this_zip)

            # 6) Processiamo eventuali .p7m rimasti (a ogni livello) dentro target_root_for_this_zip
            process_directory_for_p7m(target_root_for_this_zip, f"{nome_base}")

            # 7) Pulizia di cartelle contenenti solo .p7m non processati
            cleanup_unprocessed_p7m_dirs(target_root_for_this_zip)

            # 8) Rimozione di eventuali cartelle “*.zip” ridondanti
            cleanup_extra_zip_named_dirs(target_root_for_this_zip)

            # 9) Rimuovo la cartella temporanea usata per l’estrazione iniziale
            shutil.rmtree(temp_zip_dir, ignore_errors=True)

        elif suff == ".p7m":
            st.write(f"🔄 Rilevato file .p7m: {nome}")

            # 1) Metto il .p7m in una cartella temporanea
            temp_single = Path(tempfile.mkdtemp(prefix="single_p7m_"))
            p7m_path = temp_single / nome
            with open(p7m_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            # 2) Estraggo direttamente in root_temp (flat)
            payload_path, signer_name, firma_ok = extract_signed_content(p7m_path, root_temp)
            if not payload_path:
                shutil.rmtree(temp_single, ignore_errors=True)
                continue

            # 3) Rimuovo il .p7m
            try:
                p7m_path.unlink()
            except:
                pass

            # 4) Se è un ZIP, lo estraggo e appiattisco in root_temp, poi elimino .p7m non processati e directory “*.zip” ridondanti
            if payload_path.suffix.lower() == ".zip":
                recursive_unpack_and_flatten(root_temp)
                # Processiamo eventuali .p7m dentro le nuove sottocartelle
                for subd in root_temp.iterdir():
                    if subd.is_dir():
                        process_directory_for_p7m(subd, subd.name)
                # Pulizia di cartelle con soli .p7m non processati
                cleanup_unprocessed_p7m_dirs(root_temp)
                # Rimuovo cartelle “*.zip” ridondanti
                cleanup_extra_zip_named_dirs(root_temp)
                try:
                    payload_path.unlink()
                except:
                    pass

            # 5) Mostro in UI firmatario e stato
            colx, coly = st.columns([4, 1])
            with colx:
                st.write(f"  – File estratto: **{payload_path.name}**")
                st.write(f"    Firmato da: **{signer_name}**")
            with coly:
                if firma_ok:
                    st.success("Firma valida ✅")
                else:
                    st.error("Firma NON valida ⚠️")

            # 6) Elimino la cartella temporanea
            shutil.rmtree(temp_single, ignore_errors=True)

        else:
            st.warning(f"Ignoro «{nome}»: estensione non supportata ({suff}).")

    # --- Creo lo ZIP di output con tutta la struttura “pulita” -------------
    zip_out_path = root_temp / output_filename
    with zipfile.ZipFile(zip_out_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(root_temp):
            for file in files:
                if file == output_filename:
                    continue
                file_path = Path(root) / file
                rel_path = file_path.relative_to(root_temp)
                zipf.write(file_path, rel_path)

    # Pulsante per scaricare
    with open(zip_out_path, "rb") as f:
        st.download_button(
            label="Scarica il file ZIP con tutte le estrazioni",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )

