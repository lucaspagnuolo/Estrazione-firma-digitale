import streamlit as st
import csv
import pandas as pd
from datetime import datetime, timedelta
import io

# Utility functions
def formatta_data(data):
    for sep in ["-", "/"]:
        try:
            g, m, a = map(int, data.split(sep))
            dt = datetime(a, m, g) + timedelta(days=1)
            return dt.strftime("%m/%d/%Y 00:00")
        except:
            continue
    return data


def genera_samaccountname(
    nome: str,
    cognome: str,
    secondo_nome: str = "",
    secondo_cognome: str = "",
    esterno: bool = False
) -> str:
    n = nome.strip().lower()
    sn = secondo_nome.strip().lower() if secondo_nome else ""
    c = cognome.strip().lower()
    sc = secondo_cognome.strip().lower() if secondo_cognome else ""
    suffix = ".ext" if esterno else ""
    limit = 16 if esterno else 20
    cand = f"{n}{sn}.{c}{sc}"
    if len(cand) <= limit:
        return cand + suffix
    cand = f"{(n[0] if n else '')}{(sn[0] if sn else '')}.{c}{sc}"
    if len(cand) <= limit:
        return cand + suffix
    cand = f"{(n[0] if n else '')}{(sn[0] if sn else '')}.{c}"
    return cand[:limit] + suffix


def build_full_name(
    cognome: str,
    secondo_cognome: str,
    nome: str,
    secondo_nome: str,
    esterno: bool = False
) -> str:
    parts = [cognome, secondo_cognome, nome, secondo_nome]
    parts = [p for p in parts if p]
    full = ' '.join(parts)
    if esterno:
        full += ' (esterno)'
    return full

# Header for CSV
definizione_header = [
    "sAMAccountName", "Creation", "OU", "Name", "DisplayName", "cn", "GivenName", "Surname",
    "employeeNumber", "employeeID", "department", "Description", "passwordNeverExpired",
    "ExpireDate", "userprincipalname", "mail", "mobile", "RimozioneGruppo", "InserimentoGruppo",
    "disable", "moveToOU", "telephoneNumber", "company"
]

# Process functions for each subtype
def process_interna():
    st.header("1.1 Nuova Risorsa Interna")
    nome = st.text_input("Nome").strip().capitalize()
    secondo_nome = st.text_input("Secondo Nome").strip().capitalize()
    cognome = st.text_input("Cognome").strip().capitalize()
    secondo_cognome = st.text_input("Secondo Cognome").strip().capitalize()
    numero_telefono = st.text_input("Numero di Telefono", "").replace(" ", "")
    description = st.text_input("Description (lascia vuoto per <PC>)", "<PC>").strip()
    codice_fiscale = st.text_input("Codice Fiscale", "").strip()

    ou = st.selectbox("OU", ["Utenti standard", "Utenti VIP"])
    employee_id = st.text_input("Employee ID", "").strip()
    department = st.text_input("Dipartimento", "").strip()
    inserimento_gruppo = (
        "consip_vpn;dipendenti_wifi;mobile_wifi;"
        "GEDOGA-P-DOCGAR;GRPFreeDeskUser"
    )
    telephone_number = "+39 06 854491"
    company = "Consip"

    if st.button("Genera CSV Interna"):
        genera_csv(False, nome, secondo_nome, cognome, secondo_cognome,
                   numero_telefono, description, codice_fiscale,
                   ou, employee_id, department, inserimento_gruppo,
                   telephone_number, company)


def process_esterna_stage():
    st.header("1.2 Risorsa Esterna: Somministrato/Stage")
    nome = st.text_input("Nome").strip().capitalize()
    secondo_nome = st.text_input("Secondo Nome").strip().capitalize()
    cognome = st.text_input("Cognome").strip().capitalize()
    secondo_cognome = st.text_input("Secondo Cognome").strip().capitalize()
    numero_telefono = st.text_input("Numero di Telefono", "").replace(" ", "")
    description = st.text_input("Description (lascia vuoto per <PC>)", "<PC>").strip()
    codice_fiscale = st.text_input("Codice Fiscale", "").strip()

    expire_date = st.text_input("Data di Fine (gg-mm-aaaa)", "30-06-2025").strip()
    ou = "Utenti esterni - Somministrati e Stage"
    employee_id = ""
    department = st.text_input("Dipartimento").strip()
    inserimento_gruppo = "consip_vpn;dipendenti_wifi;mobile_wifi;GRPFreeDeskUser"
    telephone_number = ""
    company = ""

    email_flag = st.radio("Email necessaria?", ["Sì", "No"]) == "Sì"
    if email_flag:
        try:
            email = f"{cognome.lower()}{nome[0].lower()}@consip.it"
        except IndexError:
            st.error("Per email automatica inserisci Nome e Cognome.")
            email = ""
    else:
        email = genera_samaccountname(nome, cognome, secondo_nome, secondo_cognome) + "@consip.it"

    if st.button("Genera CSV Esterna Stage"):
        genera_csv(True, nome, secondo_nome, cognome, secondo_cognome,
                   numero_telefono, description, codice_fiscale,
                   ou, employee_id, department, inserimento_gruppo,
                   telephone_number, company,
                   expire_date, email_flag=email_flag, custom_email=email)


def process_esterna_consulente():
    st.header("1.3 Risorsa Esterna: Consulente")
    nome = st.text_input("Nome").strip().capitalize()
    secondo_nome = st.text_input("Secondo Nome").strip().capitalize()
    cognome = st.text_input("Cognome").strip().capitalize()
    secondo_cognome = st.text_input("Secondo Cognome").strip().capitalize()
    numero_telefono = st.text_input("Numero di Telefono", "").replace(" ", "")
    description = st.text_input("Description (lascia vuoto per <PC>)", "<PC>").strip()
    codice_fiscale = st.text_input("Codice Fiscale", "").strip()

    expire_date = st.text_input("Data di Fine (gg-mm-aaaa)", "30-06-2025").strip()
    ou = "Utenti esterni - Consulenti"
    employee_id = ""
    department = "Utente esterno"
    inserimento_gruppo = "consip_vpn"
    telephone_number = ""
    company = ""

    email_flag = st.radio("Email necessaria?", ["Sì", "No"]) == "Sì"
    if email_flag:
        email = st.text_input("Email Personalizzata").strip()
    else:
        email = genera_samaccountname(nome, cognome, secondo_nome, secondo_cognome) + "@consip.it"

    if st.button("Genera CSV Esterna Consulente"):
        genera_csv(True, nome, secondo_nome, cognome, secondo_cognome,
                   numero_telefono, description, codice_fiscale,
                   ou, employee_id, department, inserimento_gruppo,
                   telephone_number, company,
                   expire_date, email_flag=email_flag, custom_email=email)


def genera_csv(
    esterno, nome, secondo_nome, cognome, secondo_cognome,
    numero_telefono, description, codice_fiscale,
    ou, employee_id, department, inserimento_gruppo,
    telephone_number, company,
    expire_date=None, email_flag=False, custom_email=None
):
    sAMAccountName = genera_samaccountname(nome, cognome, secondo_nome, secondo_cognome, esterno)
    cn = build_full_name(cognome, secondo_cognome, nome, secondo_nome, esterno)
    nome_completo = cn.replace(" (esterno)", "")
    display_name = cn
    expire_fmt = formatta_data(expire_date) if esterno else ""
    upn = f"{sAMAccountName}@consip.it"
    mobile = f"+39 {numero_telefono}" if numero_telefono else ""
    desc = description or "<PC>"
    mail = custom_email if (esterno and email_flag) else f"{sAMAccountName}@consip.it"
    given = ' '.join([nome, secondo_nome]).strip()
    surn = ' '.join([cognome, secondo_cognome]).strip()

    row = [
        sAMAccountName, "SI", ou, nome_completo, display_name,
        cn, given, surn, codice_fiscale,
        employee_id, department, desc, "No", expire_fmt,
        upn, mail, mobile, "", inserimento_gruppo, "", "",
        telephone_number, company
    ]

    buf = io.StringIO()
    wr = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    wr.writerow(definizione_header)
    wr.writerow(row)
    buf.seek(0)

    df = pd.DataFrame([row], columns=definizione_header)
    st.dataframe(df)

    st.download_button(
        label="📥 Scarica CSV Utente",
        data=buf.getvalue(),
        file_name=f"{cognome}_{nome[:1]}_utente.csv",
        mime="text/csv"
    )
    st.success(f"✅ File CSV generato per '{sAMAccountName}'")

# Main app
st.title("Gestione Inserimento Nuove Risorse Consip")
processo = st.selectbox(
    "Seleziona Processo:",
    ["1. Inserimento Nuova Risorsa"]
)

if processo == "1. Inserimento Nuova Risorsa":
    scelta = st.selectbox(
        "Seleziona tipologia risorsa:",
        ["1.1 Nuova Risorsa Interna", 
         "1.2 Risorsa Esterna: Somministrato/Stage",
         "1.3 Risorsa Esterna: Consulente"]
    )
    if scelta == "1.1 Nuova Risorsa Interna":
        process_interna()
    elif scelta == "1.2 Risorsa Esterna: Somministrato/Stage":
        process_esterna_stage()
    elif scelta == "1.3 Risorsa Esterna: Consulente":
        process_esterna_consulente()
