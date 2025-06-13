import streamlit as st
import os
import zipfile
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import re
import pandas as pd
from PIL import Image

# --- Layout con logo a destra ---------------------------------------------
col1, col2 = st.columns([7, 3])
with col1:
    st.title("Estrattore di file firmati digitalmente (CAdES)")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# --- Funzione per estrarre payload e certificato --------------------------
def extract_signed_content(p7m_path: Path, output_dir: Path) -> tuple[Path | None, str, bool]:
    base = p7m_path.stem
    out_file = output_dir / base

    # Verifica payload
    cmd = ["openssl", "cms", "-verify", "-in", str(p7m_path), "-inform", "DER", "-noverify", "-out", str(out_file)]
    res = subprocess.run(cmd, capture_output=True)
    if res.returncode != 0:
        st.error(f"Errore estrazione {p7m_path.name}: {res.stderr.decode().strip()}")
        return None, "", False

    # Rinomina ZIP
    try:
        with open(out_file, "rb") as f:
            if f.read(4) == b"PK\x03\x04":
                newz = out_file.with_suffix(".zip")
                out_file.rename(newz)
                out_file = newz
    except Exception:
        pass

    # Estrai certificato
    cert_pem = output_dir / f"{base}_cert.pem"
    cmd2 = ["openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_path), "-print_certs", "-out", str(cert_pem)]
    subprocess.run(cmd2, capture_output=True)

    # Leggi subject e validity
    cmd3 = ["openssl", "x509", "-in", str(cert_pem), "-noout", "-subject", "-dates"]
    proc = subprocess.run(cmd3, capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    signer = "Sconosciuto"
    if proc.returncode == 0:
        txt = proc.stdout
        for rdn in ["CN", "emailAddress"]:
            m = re.search(rf"{rdn}=([^,/]+)", txt)
            if m:
                signer = m.group(1).strip()
                break
        def pd(s): return datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z")
        lines = txt.splitlines()
        nb = next(l for l in lines if "notBefore" in l).split("=",1)[1]
        na = next(l for l in lines if "notAfter" in l).split("=",1)[1]
        valid = pd(nb) <= datetime.utcnow() <= pd(na)
    else:
        valid = False

    return out_file, signer, valid

# --- Unpack ricorsivo con pulizia wrapper -------------------------------
def recursive_unpack(directory: Path):
    for z in list(directory.rglob("*.zip")):
        if not z.is_file():
            continue
        tgt = z.parent / f"{z.stem}_unzipped"
        if tgt.exists(): shutil.rmtree(tgt)
        tgt.mkdir()
        try:
            with zipfile.ZipFile(z, 'r') as zf:
                zf.extractall(tgt)
        except:
            z.unlink(missing_ok=True)
            continue
        z.unlink()
        # se unico subfolder, sposta
        subs = list(tgt.iterdir())
        if len(subs)==1 and subs[0].is_dir():
            for f in subs[0].iterdir(): shutil.move(str(f), str(tgt))
            subs[0].rmdir()
        recursive_unpack(tgt)

# --- Processa .p7m in dir ------------------------------------------------
def process_dir(directory: Path, prefix: str):
    for p7m in directory.rglob("*.p7m"):
        rel = p7m.relative_to(directory)
        st.write(f"{prefix} · {rel.parent}: {p7m.name}")
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        p7m.unlink(missing_ok=True)
        if not payload:
            continue
        if payload.suffix == ".zip":
            recursive_unpack(payload.parent)
            sub = payload.parent / payload.stem
            if sub.is_dir(): process_dir(sub, prefix+"  ")
            if payload.exists(): payload.unlink()
        c1, c2 = st.columns([4,1])
        with c1:
            st.write(f"– Estratto: **{payload.name}**")
            st.write(f"  Firmato da: **{signer}**")
        with c2:
            if valid: st.success("Firma valida ✅")
            else:     st.error("Firma NON valida ⚠️")

# --- Streamlit UI e ZIP finale ------------------------------------------
output_name = st.text_input("Nome ZIP output:", "all_extracted.zip")
if not output_name.lower().endswith(".zip"): output_name += ".zip"
uploaded = st.file_uploader("Carica .zip o .p7m", accept_multiple_files=True)
if uploaded:
    root = Path(tempfile.mkdtemp(prefix="combined_"))
    for uf in uploaded:
        tmp = Path(tempfile.mkdtemp(prefix="up_"))
        fpath = tmp/uf.name; fpath.write_bytes(uf.getbuffer())
        if fpath.suffix == ".zip":
            with zipfile.ZipFile(fpath,'r') as zf: zf.extractall(tmp)
            recursive_unpack(tmp)
            for d in tmp.iterdir():
                if d.is_dir(): shutil.copytree(d, root/d.name, dirs_exist_ok=True)
        elif fpath.suffix == ".p7m":
            extract_signed_content(fpath, root)
        shutil.rmtree(tmp, ignore_errors=True)

    for d in root.iterdir():
        if d.is_dir(): process_dir(d, d.name)

    # ZIP finale escludendo wrapper
    outd = Path(tempfile.mkdtemp(prefix="out_"))
    zipf = zipfile.ZipFile(outd/output_name,'w',compression=zipfile.ZIP_DEFLATED)
    for base,dirs,files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.endswith("_unzipped")]
        for f in files:
            p = Path(base)/f
            zipf.write(p, p.relative_to(root).as_posix())
    zipf.close()

    # download
    with open(outd/output_name,'rb') as f:
        st.download_button("Scarica ZIP", data=f, file_name=output_name, mime="application/zip")

    # anteprima
    st.subheader("Anteprima struttura ZIP")
    with zipfile.ZipFile(outd/output_name,'r') as pf:
        paths = [i.filename for i in pf.infolist()]
    rows = [p.split("/") for p in paths]
    df = pd.DataFrame(rows)
    df.columns = [f"Livello {i+1}" for i in range(df.shape[1])]
    for c in df.columns: df[c] = df[c].mask(df[c]==df[c].shift(),"")
    st.table(df)
