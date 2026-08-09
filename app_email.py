import streamlit as st
import email
from email import policy
from email.parser import BytesParser, Parser
import re
from bs4 import BeautifulSoup
import pandas as pd

# Konfigurasi Halaman
st.set_page_config(page_title="Email Header & Phishing Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Email Header & Phishing Analyzer")
st.caption("Alat analisis defensif untuk mendeteksi keaslian pengirim dan indikasi manipulasi email.")

# Sidebar Pilihan Input
st.sidebar.header("📥 Sumber Email")
mode_input = st.sidebar.radio("Pilih Cara Unggah:", ["File .EML", "Tempel Raw Header (Teks)"])

raw_email_obj = None

if mode_input == "File .EML":
    uploaded_eml = st.file_uploader("Unggah file email (.eml):", type=['eml'])
    if uploaded_eml:
        raw_email_obj = BytesParser(policy=policy.default).parse(uploaded_eml)
else:
    header_text = st.text_area("Tempelkan Raw Header / Teks Email di sini:", height=200)
    if header_text.strip():
        raw_email_obj = Parser(policy=policy.default).parsestr(header_text)

# Fungsi Pendukung
def ekstrak_url_dari_text(text):
    """Mencari seluruh URL di dalam teks biasa."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def ekstrak_url_dari_html(html_content):
    """Mengekstrak tautan dari HTML beserta Teks Tautan (Anchor Text)."""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = []
    for a in soup.find_all('a', href=True):
        links.append({
            "Teks Tautan (Visual)": a.get_text().strip() or "[Gambar / Tanpa Teks]",
            "URL Tujuan Asli": a['href']
        })
    return links

# Pemrosesan jika data email tersedia
if raw_email_obj:
    tab1, tab2, tab3 = st.tabs(["📋 Ringkasan & Autentikasi", "🛤️ Rute Transit (Received Hops)", "🔗 Analisis Tautan & URL"])

    # --------------------------------------------------------------------------
    # TAB 1: RINGKASAN & STATUS AUTENTIKASI (SPF/DKIM/DMARC)
    # --------------------------------------------------------------------------
    with tab1:
        st.subheader("📧 Metadata Utama Email")
        
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**From (Pengirim):** `{raw_email_obj.get('From', 'N/A')}`")
            st.write(f"**To (Penerima):** `{raw_email_obj.get('To', 'N/A')}`")
            st.write(f"**Reply-To:** `{raw_email_obj.get('Reply-To', 'Tidak diatur (Sesuai From)')}`")
        with col2:
            st.write(f"**Subject:** `{raw_email_obj.get('Subject', 'N/A')}`")
            st.write(f"**Date:** `{raw_email_obj.get('Date', 'N/A')}`")
            st.write(f"**Message-ID:** `{raw_email_obj.get('Message-ID', 'N/A')}`")

        # Peringatan dini jika Reply-To berbeda dengan From (Indikasi Phishing)
        from_hdr = str(raw_email_obj.get('From', ''))
        reply_hdr = str(raw_email_obj.get('Reply-To', ''))
        if reply_hdr and reply_hdr != from_hdr:
            st.warning("⚠️ **Perhatian:** Alamat `Reply-To` berbeda dengan `From`. Jawaban email ini akan terkirim ke alamat yang berbeda dari pengirim yang terlihat!")

        st.markdown("---")
        st.subheader("🔑 Hasil Validasi Autentikasi Email")

        auth_results = raw_email_obj.get('Authentication-Results', '')
        received_spf = raw_email_obj.get('Received-SPF', '')

        col_spf, col_dkim, col_dmarc = st.columns(3)

        # Pemeriksaan Sederhana Keyword Pass/Fail
        auth_text = f"{auth_results} {received_spf}".lower()

        with col_spf:
            if "spf=pass" in auth_text or "pass" in received_spf.lower():
                st.success("✅ **SPF:** PASS")
            elif "spf=fail" in auth_text or "fail" in received_spf.lower():
                st.error("❌ **SPF:** FAIL / SOFTFAIL")
            else:
                st.info("ℹ️ **SPF:** Tidak Terdeteksi")

        with col_dkim:
            if "dkim=pass" in auth_text:
                st.success("✅ **DKIM:** PASS")
            elif "dkim=fail" in auth_text:
                st.error("❌ **DKIM:** FAIL")
            else:
                st.info("ℹ️ **DKIM:** Tidak Terdeteksi")

        with col_dmarc:
            if "dmarc=pass" in auth_text:
                st.success("✅ **DMARC:** PASS")
            elif "dmarc=fail" in auth_text:
                st.error("❌ **DMARC:** FAIL")
            else:
                st.info("ℹ️ **DMARC:** Tidak Terdeteksi")

        with st.expander("📄 Lihat Raw Authentication Header"):
            st.code(f"Authentication-Results: {auth_results}\nReceived-SPF: {received_spf}")

    # --------------------------------------------------------------------------
    # TAB 2: RUTE TRANSIT EMAIL (RECEIVED HOPS)
    # --------------------------------------------------------------------------
    with tab2:
        st.subheader("🛤️ Melacak Perjalanan Server Email (Hops)")
        st.write("Email berpindah dari server pengirim awal ke server penerima. Urutan terbawah adalah server paling awal.")

        received_headers = raw_email_obj.get_all('Received', [])
        if received_headers:
            hops_data = []
            for idx, hop in enumerate(reversed(received_headers), 1):
                hops_data.append({
                    "Langkah": f"Hop #{idx}",
                    "Detail Server / IP Transit": hop.strip().replace("\n", " ").replace("\t", " ")
                })
            
            st.table(pd.DataFrame(hops_data))
        else:
            st.info("Tidak ditemukan header 'Received' pada data yang dimasukkan.")

    # --------------------------------------------------------------------------
    # TAB 3: EKSTRAKSI & DETEKSI URL
    # --------------------------------------------------------------------------
    with tab3:
        st.subheader("🔗 Deteksi Tautan / URL Tersembunyi")

        body_html = ""
        body_text = ""

        if raw_email_obj.is_multipart():
            for part in raw_email_obj.walk():
                content_type = part.get_content_type()
                if content_type == 'text/html':
                    body_html += part.get_payload(decode=True).decode(errors='ignore')
                elif content_type == 'text/plain':
                    body_text += part.get_payload(decode=True).decode(errors='ignore')
        else:
            if raw_email_obj.get_content_type() == 'text/html':
                body_html = raw_email_obj.get_payload(decode=True).decode(errors='ignore')
            else:
                body_text = raw_email_obj.get_payload(decode=True).decode(errors='ignore')

        found_links = []
        if body_html:
            found_links = ekstrak_url_dari_html(body_html)
            if found_links:
                st.write("Daftar tautan dari format **HTML**:")
                df_links = pd.DataFrame(found_links)
                st.dataframe(df_links, use_container_width=True)

                # Deteksi tautan tersembunyi/mengecoh
                for item in found_links:
                    vis = item['Teks Tautan (Visual)']
                    target = item['URL Tujuan Asli']
                    if (vis.startswith("http://") or vis.startswith("https://")) and vis != target:
                        st.error(f"🚨 **Indikasi Mismatch / Phishing!** Teks visual menampilkan `{vis}` tetapi tombol mengarah ke `{target}`.")
        
        elif body_text:
            text_links = ekstrak_url_dari_text(body_text)
            if text_links:
                st.write("Daftar tautan dari format **Plain Text**:")
                for url in set(text_links):
                    st.code(url)
            else:
                st.info("Tidak ditemukan tautan URL pada isi email.")
        else:
            st.info("Isi pesan email tidak dapat dibaca atau tidak mengandung tautan.")
