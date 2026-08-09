import streamlit as st
import email
from email import policy
from email.parser import BytesParser, Parser
import re
from bs4 import BeautifulSoup
import pandas as pd
import requests

# Konfigurasi Halaman
st.set_page_config(page_title="Email Header & Phishing Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Email Header & Phishing Analyzer + Threat Intel")
st.caption("Alat analisis defensif untuk mendeteksi keaslian pengirim dan mengecek reputasi IP/URL via API Gratis.")

# Sidebar - Sumber Email
st.sidebar.header("📥 Sumber Email")
mode_input = st.sidebar.radio("Pilih Cara Unggah:", ["File .EML", "Tempel Raw Header (Teks)"])

# Sidebar - API Keys (Opsional & Gratis)
st.sidebar.markdown("---")
st.sidebar.header("🔑 Kunci API Threat Intel (Gratis)")
abuseipdb_key = st.sidebar.text_input("AbuseIPDB API Key:", type="password", help="Dapatkan gratis di abuseipdb.com (1.000 req/hari)")
virustotal_key = st.sidebar.text_input("VirusTotal API Key:", type="password", help="Dapatkan gratis di virustotal.com (500 req/hari)")

raw_email_obj = None

if mode_input == "File .EML":
    uploaded_eml = st.file_uploader("Unggah file email (.eml):", type=['eml'])
    if uploaded_eml:
        raw_email_obj = BytesParser(policy=policy.default).parse(uploaded_eml)
else:
    header_text = st.text_area("Tempelkan Raw Header / Teks Email di sini:", height=200)
    if header_text.strip():
        raw_email_obj = Parser(policy=policy.default).parsestr(header_text)

# Fungsi Extractor & Integrasi API
def ekstrak_ip(text):
    """Mengekstrak alamat IPv4 dari teks header."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    # Filter IP privat/lokal (127.0.0.1, 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    public_ips = []
    for ip in ips:
        if not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")):
            public_ips.append(ip)
    return list(dict.fromkeys(public_ips))  # Hapus duplikat

def cek_abuseipdb(ip, api_key):
    """Pemeriksaan reputasi IP menggunakan API AbuseIPDB."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            return res.json()['data']
    except Exception:
        pass
    return None

def ekstrak_url_dari_html(html_content):
    """Mengekstrak tautan dari HTML beserta Teks Visualnya."""
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
    tab1, tab2, tab3 = st.tabs(["📋 Ringkasan & Autentikasi", "🛤️ Rute Transit & Cek IP", "🔗 Analisis Tautan & URL"])

    # --------------------------------------------------------------------------
    # TAB 1: RINGKASAN & AUTENTIKASI
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

        # Peringatan dini jika Reply-To berbeda dengan From
        from_hdr = str(raw_email_obj.get('From', ''))
        reply_hdr = str(raw_email_obj.get('Reply-To', ''))
        if reply_hdr and reply_hdr != from_hdr:
            st.warning("⚠️ **Perhatian:** Alamat `Reply-To` berbeda dengan `From`. Jawaban email ini akan terkirim ke alamat lain!")

        st.markdown("---")
        st.subheader("🔑 Hasil Validasi Autentikasi Email")

        auth_results = str(raw_email_obj.get('Authentication-Results', ''))
        received_spf = str(raw_email_obj.get('Received-SPF', ''))
        auth_text = f"{auth_results} {received_spf}".lower()

        col_spf, col_dkim, col_dmarc = st.columns(3)
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

    # --------------------------------------------------------------------------
    # TAB 2: RUTE TRANSIT & CEK REPUTASI IP (ABUSEIPDB)
    # --------------------------------------------------------------------------
    with tab2:
        st.subheader("🛤️ Melacak Perjalanan Server Email & Reputasi IP")
        
        received_headers = raw_email_obj.get_all('Received', [])
        all_text = " ".join(received_headers) if received_headers else ""
        extracted_ips = ekstrak_ip(all_text)

        if extracted_ips:
            st.write(f"Terdeteksi **{len(extracted_ips)} Alamat IP Publik** dalam perjalanan email.")
            
            for ip in extracted_ips:
                with st.expander(f"📍 Analisis IP: {ip}"):
                    st.write(f"**IP Address:** `{ip}`")
                    
                    if abuseipdb_key:
                        data_ip = cek_abuseipdb(ip, abuseipdb_key)
                        if data_ip:
                            skor = data_ip.get('abuseConfidenceScore', 0)
                            negara = data_ip.get('countryCode', 'N/A')
                            isp = data_ip.get('isp', 'N/A')
                            total_laporan = data_ip.get('totalReports', 0)

                            if skor > 50:
                                st.error(f"🚨 **SKOR ANCAMAN TINGGI:** {skor}% Abuse Confidence!")
                            elif skor > 20:
                                st.warning(f"⚠️ **SKOR SEDANG:** {skor}% Abuse Confidence.")
                            else:
                                st.success(f"✅ **IP Bersih:** Skor Penyalahgunaan {skor}%")

                            st.write(f"* **Negara Asal:** `{negara}`")
                            st.write(f"* **Penyedia Layanan (ISP):** `{isp}`")
                            st.write(f"* **Total Laporan Kejahatan:** `{total_laporan} kali`")
                        else:
                            st.error("Gagal mengambil data dari API AbuseIPDB. Periksa Kunci API Anda.")
                    else:
                        st.info("💡 **TIPS:** Masukkan **AbuseIPDB API Key** di menu sebelah kiri (Sidebar) untuk melihat tingkat bahaya dan negara asal IP ini secara otomatis.")
        else:
            st.info("Tidak ditemukan alamat IP publik pada header 'Received'.")

    # --------------------------------------------------------------------------
    # TAB 3: EKSTRAKSI & ANALISIS URL
    # --------------------------------------------------------------------------
    with tab3:
        st.subheader("🔗 Deteksi Tautan / URL Tersembunyi")

        body_html = ""
        if raw_email_obj.is_multipart():
            for part in raw_email_obj.walk():
                if part.get_content_type() == 'text/html':
                    body_html += part.get_payload(decode=True).decode(errors='ignore')
        else:
            if raw_email_obj.get_content_type() == 'text/html':
                body_html = raw_email_obj.get_payload(decode=True).decode(errors='ignore')

        if body_html:
            found_links = ekstrak_url_dari_html(body_html)
            if found_links:
                df_links = pd.DataFrame(found_links)
                st.dataframe(df_links, use_container_width=True)

                for item in found_links:
                    vis = item['Teks Tautan (Visual)']
                    target = item['URL Tujuan Asli']
                    if (vis.startswith("http://") or vis.startswith("https://")) and vis != target:
                        st.error(f"🚨 **Indikasi Mismatch / Phishing!** Teks visual menampilkan `{vis}`, tetapi mengarahkan ke `{target}`.")
            else:
                st.info("Tidak ada tautan HTML yang ditemukan.")
        else:
            st.info("Format email ini tidak menggunakan HTML.")
