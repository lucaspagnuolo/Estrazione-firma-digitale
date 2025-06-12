import streamlit as st
import os
import zipfile
import subprocess
import tempfile
import shutil
import pathlib
from pathlib import Path
from datetime import datetime
import re
from PIL import Image
import pandas as pd

# --- Layout con logo a destra ---------------------------------------------
col1, col2 = st.columns([7, 3])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# --- Funzione che esegue openssl cms -verify e legge il certificato -------
def extract_signed_content(p7m_file_path: Path, output_dir: Path) -> tuple[Path | None, str, bool]:
    payload_basename = p7m_file_path.stem
    output_file = output_dir / payload_basename

    # 1) Estraggo il payload
    cmd1 = ["openssl", "cms", "-verify", "-in", str(p7m_file_path), "-inform", "DER", "-noverify", "-out", str(output_file)]
    res1 = subprocess.run(cmd1, capture_output=True)
    if res1.returncode != 0:
        st.error(f"Errore estrazione «{p7m_file_path.name}»: {res1.stderr.decode().strip()}")
        return None, "", False

    # 2) Estrazione certificato in PEM
    cert_pem = output_dir / (payload_basename + "_cert.pem")
    cmd2 = ["openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_file_path), "-print_certs", "-out", str(cert_pem)]
    res2 = subprocess.run(cmd2, capture_output=True)
    if res2.returncode != 0:
        st.error(f"Errore estrazione certificato: {res2.stderr.decode().strip()}")
        return output_file, "Sconosciuto", False

    # 3) Leggo subject e validity
    cmd3 = ["openssl", "x509", "-in", str(cert_pem), "-noout", "-subject", "-dates"]
    res3 = subprocess.run(cmd3, capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    if res3.returncode != 0:
        st.error(f"Errore lettura certificato: {res3.stderr.strip()}")
        return output_file, "Sconosciuto", False

    lines = res3.stdout.splitlines()
    signer = "Sconosciuto"
    for rdn in ["CN", "SN", "UID", "emailAddress", "SERIALNUMBER"]:
        m = re.search(rf"{rdn}\s*=\s*([^,/]+)", "\n".join(lines))
        if m:
            signer = m.group(1).strip()
            break

    def parse_date(s: str) -> datetime:
        return datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z")
    try:
        nb = parse_date(next(l for l in lines if "notBefore" in l).split("=",1)[1])
        na = parse_date(next(l for l in lines if "notAfter" in l).split("=",1)[1])
        valid = nb <= datetime.utcnow() <= na
    except:
        valid = False

    # 4) Se payload è ZIP, rinomino
    try:
        with open(output_file, "rb") as f:
            if f.read(4).startswith(b"PK\x03\x04"):
                new = output_file.with_suffix(".zip")
                output_file.rename(new)
                output_file = new
    except:
        pass

    return output_file, signer, valid

# --- Disimballa ricorsivamente e appiattisce ZIP ---------------------------
def recursive_unpack(d: Path):
    for z in list(d.rglob("*.zip")):
        if not z.is_file(): 
            continue
        tgt = z.parent / f"{z.stem}_unzipped"
        if tgt.exists():
            shutil.rmtree(tgt)
        tgt.mkdir()
        try:
            with zipfile.ZipFile(z) as zf:
                zf.extractall(tgt)
        except Exception:
            st.warning(f"ZIP corrotto, salto {z.name}")
            z.unlink(missing_ok=True)
            continue
        z.unlink()
        # se contiene una singola cartella, risalgo
        items = list(tgt.iterdir())
        if len(items) == 1 and items[0].is_dir():
            for f in items[0].iterdir():
                shutil.move(str(f), str(tgt))
            items[0].rmdir()
        recursive_unpack(tgt)

# --- Rimuove cartelle duplicate/extra -------------------------------------
def remove_duplicates(root: Path):
    for dp, dn, _ in os.walk(root):
        for d in dn:
            p = Path(dp) / d
            files_parent = sorted(f.name for f in Path(dp).iterdir() if f.is_file())
            files_child  = sorted(f.name for f in p.iterdir() if f.is_file())
            if files_parent == files_child:
                shutil.rmtree(p)

def cleanup_p7m_dirs(root: Path):
    for d in sorted(root.rglob("*"), key=lambda p: -len(p.parts)):
        if d.is_dir() and all(f.suffix.lower() == ".p7m" for f in d.iterdir()):
            shutil.rmtree(d)

# --- Processa directory con .p7m ------------------------------------------
def process_p7m_dir(dir: Path, indent: str = ""):
    for p7m in dir.rglob("*.p7m"):
        rel = p7m.relative_to(dir)
        st.write(f"{indent}Trovato .p7m: {rel}")
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        st.write(f"→ payload={payload}, signer={signer}, valid={valid}")
        if not payload:
            continue
        p7m.unlink()
        if payload.suffix.lower() == ".zip":
            recursive_unpack(payload.parent)
            newd = payload.parent / payload.stem
            if newd.exists():
                process_p7m_dir(newd, indent + "  ")
            payload.unlink()
        c1, c2 = st.columns([4, 1])
        with c1:
            st.write(f"- Estratto: **{payload.name}**, firmato da **{signer}**")
        with c2:
            if valid:
                st.success("✅")
            else:
                st.error("⚠️")

# --- Streamlit UI ---------------------------------------------------------
output_name = st.text_input("Nome ZIP output (includi .zip):", "all_extracted.zip")
if not output_name.lower().endswith(".zip"):
    output_name += ".zip"

files = st.file_uploader("Carica .p7m o ZIP con .p7m", accept_multiple_files=True)

if files:
    root = Path(tempfile.mkdtemp())
    for up in files:
        ext = Path(up.name).suffix.lower()
        tmp = Path(tempfile.mkdtemp())
        dst = tmp / up.name
        with open(dst, "wb") as f:
            f.write(up.getbuffer())

        if ext == ".zip":
            try:
                with zipfile.ZipFile(dst) as z:
                    z.extractall(tmp)
            except:
                st.error(f"ZIP corrotto: {up.name}")
            recursive_unpack(tmp)
            target = root / pathlib.Path(up.name).stem
            shutil.copytree(tmp, target)
        elif ext == ".p7m":
            payload, signer, valid = extract_signed_content(dst, root)
            st.write(f"→ payload={payload}, signer={signer}, valid={valid}")
        else:
            st.warning(f"Ignoro {up.name}")

    process_p7m_dir(root)

    # Debug struttura
    st.subheader("Debug struttura")
    for r, d, fs in os.walk(root):
        indent = "  " * len(Path(r).relative_to(root).parts)
        st.write(f"{indent}- {Path(r).name}/")
        for f in fs:
            st.write(f"{indent}  - {f}")

    # Raccoglie files
    allf = [Path(r) / f for r, _, fs in os.walk(root) for f in fs if f != output_name]
    if not allf:
        st.error("Nessun file estratto per lo ZIP finale.")
    else:
        st.subheader("File pronti per ZIP finale")
        for p in allf:
            st.write(f"- {p.relative_to(root)}")

        base = tempfile.mktemp()
        shutil.make_archive(base, "zip", root)
        out = Path(f"{base}.zip")

        # Anteprima multi-livello
        with zipfile.ZipFile(out) as zf:
            paths = [i.filename for i in zf.infolist()]
        if paths:
            splits = [p.split("/") for p in paths]
            maxl = max((len(s) for s in splits), default=0)
            cols = [f"Livello {i+1}" for i in range(maxl)]
            data = [s + [""] * (maxl - len(s)) for s in splits]
            df = pd.DataFrame(data, columns=cols)
            for c in cols:
                df[c] = df[c].mask(df[c] == df[c].shift(), "")
            st.subheader("Struttura ZIP finale")
            st.table(df)
        else:
            st.info("ZIP finale vuoto. Nessuna anteprima.")

        # Download
        with open(out, "rb") as f:
            st.download_button("Scarica ZIP", data=f, file_name=output_name, mime="application/zip")
