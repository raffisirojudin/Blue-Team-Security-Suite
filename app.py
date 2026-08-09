import streamlit as st
import email
from email import policy
from email.parser import BytesParser, Parser
import re
from bs4 import BeautifulSoup
import pandas as pd
import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

# Konfigurasi Halaman Web
st.set_page_config(page_title="Blue Team Security Suite", page_icon="🛡️", layout="wide")

st.title("🛡️ Blue Team Security Suite")
st.caption("Platform analisis keamanan defensif terpadu untuk pengujian Email Phishing dan Audit Keamanan Web/SSL.")

# Navigasi Modul Utama (Top Tabs)
modul_email, modul_web, modul_hash, modul_dns = st.tabs([
    "📧 Modul 1: Email Header & Phishing Analyzer", 
    "🌐 Modul 2: Website Security Headers & SSL Auditor",
    "🔑 Modul 3: File Hash & Integrity Checker",
    "🔍 Modul 4: DNS Security Inspector"
])

# ==============================================================================
# MODUL 1: EMAIL HEADER & PHISHING ANALYZER
# ==============================================================================
with modul_email:
    st.markdown("### 📧 Email Header & Phishing Analyzer")
    st.write("Analisis file `.eml` atau *raw header* email untuk memeriksa otentikasi pengirim dan tautan berbahaya.")

    st.sidebar.header("📥 Input Email")
    mode_input = st.sidebar.radio("Pilih Cara Unggah Email:", ["File .EML", "Tempel Raw Header (Teks)"], key="mode_email_input")

    raw_email_obj = None

    if mode_input == "File .EML":
        uploaded_eml = st.file_uploader("Unggah file email (.eml):", type=['eml'], key="uploader_eml")
        if uploaded_eml:
            raw_email_obj = BytesParser(policy=policy.default).parse(uploaded_eml)
    else:
        header_text = st.text_area("Tempelkan Raw Header / Teks Email di sini:", height=180, key="area_eml_text")
        if header_text.strip():
            raw_email_obj = Parser(policy=policy.default).parsestr(header_text)

    def ekstrak_url_dari_text(text):
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        return re.findall(url_pattern, text)

    def ekstrak_url_dari_html(html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            links.append({
                "Teks Tautan (Visual)": a.get_text().strip() or "[Gambar / Tanpa Teks]",
                "URL Tujuan Asli": a['href']
            })
        return links

    if raw_email_obj:
        sub_tab1, sub_tab2, sub_tab3 = st.tabs(["📋 Ringkasan & Autentikasi", "🛤️ Rute Transit (Hops)", "🔗 Analisis Tautan & URL"])

        with sub_tab1:
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

            from_hdr = str(raw_email_obj.get('From', ''))
            reply_hdr = str(raw_email_obj.get('Reply-To', ''))
            if reply_hdr and reply_hdr != from_hdr and reply_hdr != 'None':
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

        with sub_tab2:
            st.subheader("🛤️ Melacak Perjalanan Server Email (Hops)")
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
                st.info("Tidak ditemukan header 'Received' pada data email.")

        with sub_tab3:
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

            if body_html:
                found_links = ekstrak_url_dari_html(body_html)
                if found_links:
                    st.dataframe(pd.DataFrame(found_links), use_container_width=True)
                    for item in found_links:
                        vis = item['Teks Tautan (Visual)']
                        target = item['URL Tujuan Asli']
                        if (vis.startswith("http://") or vis.startswith("https://")) and vis != target:
                            st.error(f"🚨 **Indikasi Mismatch / Phishing!** Teks visual `{vis}` mengarah ke `{target}`.")
                else:
                    st.info("Tidak ditemukan tautan HTML.")
            elif body_text:
                text_links = ekstrak_url_dari_text(body_text)
                if text_links:
                    for url in set(text_links):
                        st.code(url)
                else:
                    st.info("Tidak ditemukan tautan URL pada isi email.")


# ==============================================================================
# MODUL 2: WEBSITE SECURITY HEADERS & SSL AUDITOR
# ==============================================================================
with modul_web:
    st.markdown("### 🌐 Website Security Headers & SSL Auditor")
    st.write("Audit konfigurasi HTTP Security Headers dan masa berlaku Sertifikat SSL/TLS domain website.")

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {"nama": "HSTS", "bobot": 20, "solusi": "Strict-Transport-Security: max-age=31536000; includeSubDomains"},
        "Content-Security-Policy": {"nama": "CSP", "bobot": 25, "solusi": "Content-Security-Policy: default-src 'self'"},
        "X-Frame-Options": {"nama": "X-Frame-Options", "bobot": 15, "solusi": "X-Frame-Options: SAMEORIGIN"},
        "X-Content-Type-Options": {"nama": "X-Content-Type-Options", "bobot": 15, "solusi": "X-Content-Type-Options: nosniff"},
        "Referrer-Policy": {"nama": "Referrer-Policy", "bobot": 10, "solusi": "Referrer-Policy: strict-origin-when-cross-origin"},
        "Permissions-Policy": {"nama": "Permissions-Policy", "bobot": 15, "solusi": "Permissions-Policy: geolocation=(), camera=()"}
    }
    LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

    def normalisasi_url(url_str):
        url_str = url_str.strip()
        if not url_str.startswith(("http://", "https://")):
            url_str = "https://" + url_str
        parsed = urlparse(url_str)
        domain = parsed.netloc or parsed.path.split('/')[0]
        return url_str, domain

    def audit_ssl(domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    exp_date = datetime.strptime(cert['notAfter'], r'%b %d %H:%M:%S %Y %Z')
                    sisa_hari = (exp_date - datetime.utcnow()).days
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    issuer_name = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or "N/A"
                    return {"valid": True, "tls_version": tls_version, "exp_date": exp_date.strftime("%d %B %Y"), "sisa_hari": sisa_hari, "issuer": issuer_name}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    target_input = st.text_input("Masukkan URL/Domain Website Target:", placeholder="example.com atau https://example.com", key="input_domain_web")
    btn_audit = st.button("🔍 Audit Keamanan Web", type="primary", key="btn_audit_web")

    if btn_audit and target_input:
        full_url, domain = normalisasi_url(target_input)
        st.info(f"🔍 Menguji domain: `{domain}`")

        headers_resp = None
        http_error = None
        try:
            resp = requests.get(full_url, timeout=7, allow_redirects=True, headers={'User-Agent': 'SecurityAuditorBot/1.0'})
            headers_resp = resp.headers
        except Exception as e:
            http_error = str(e)

        ssl_info = audit_ssl(domain)

        if http_error:
            st.error(f"❌ Gagal menghubung situs target: `{http_error}`.")
        else:
            skor_total = 0
            status_headers = []

            for h_key, h_info in SECURITY_HEADERS.items():
                value = headers_resp.get(h_key)
                ada = value is not None
                if ada:
                    skor_total += h_info["bobot"]
                    status = "✅ ADA (Aman)"
                else:
                    status = "❌ HILANG"
                
                status_headers.append({
                    "Header Name": h_info["nama"],
                    "Status": status,
                    "Nilai Header": value if ada else "[Tidak Dikonfigurasi]",
                    "Solusi Rekomendasi": h_info["solusi"]
                })

            grade = "A+" if skor_total >= 85 and ssl_info["valid"] else ("B" if skor_total >= 70 else ("C" if skor_total >= 50 else "F"))

            col_g, col_s, col_ssl = st.columns(3)
            col_g.metric("Overall Security Grade", f"Grade {grade}")
            col_s.metric("Skor Security Headers", f"{skor_total} / 100")
            col_ssl.metric("Status SSL/TLS", f"Aktif ({ssl_info['sisa_hari']} Hari Sisa)" if ssl_info["valid"] else "❌ Tidak Valid")

            st.markdown("---")
            web_tab1, web_tab2, web_tab3, web_tab4 = st.tabs(["🛡️ Security Headers", "🔒 Detil SSL/TLS", "🙈 Server Leak", "📄 Kode Perbaikan"])

            with web_tab1:
                st.dataframe(pd.DataFrame(status_headers), use_container_width=True)

            with web_tab2:
                if ssl_info["valid"]:
                    st.write(f"**Versi TLS:** `{ssl_info['tls_version']}`")
                    st.write(f"**Issuer SSL:** `{ssl_info['issuer']}`")
                    st.write(f"**Kadaluwarsa:** `{ssl_info['exp_date']}` ({ssl_info['sisa_hari']} hari lagi)")
                else:
                    st.error(f"Gagal memeriksa SSL: {ssl_info.get('error')}")

            with web_tab3:
                terdapat_leak = False
                for leak in LEAK_HEADERS:
                    val = headers_resp.get(leak)
                    if val:
                        terdapat_leak = True
                        st.error(f"🚨 **Disclosed Header:** `{leak}: {val}`")
                if not terdapat_leak:
                    st.success("🎉 Tidak ada kebetoran header versi server terdeteksi.")

            with web_tab4:
                st.markdown("### Nginx Server Code")
                st.code("""add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;

add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
server_tokens off;""", language="nginx")
                
# ==============================================================================
# MODUL 3: FILE HASH & INTEGRITY CHECKER
# ==============================================================================
with modul_hash:
    st.markdown("### 🔑 File Hash & Integrity Checker")
    st.write("Hitung nilai cryptographic hash (MD5, SHA-1, SHA-256) untuk memverifikasi integritas dan keaslian berkas.")

    uploaded_file = st.file_uploader("Unggah Berkas Apapun (PDF, EXE, ZIP, Gambar, dll.):", type=None, key="uploader_hash_file")

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        
        import hashlib
        
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha1_hash = hashlib.sha1(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        st.subheader("📄 Informasi Berkas")
        col_f1, col_f2 = st.columns(2)
        col_f1.write(f"**Nama Berkas:** `{uploaded_file.name}`")
        col_f2.write(f"**Ukuran Berkas:** `{len(file_bytes) / 1024:.2f} KB` ({len(file_bytes)} bytes)")

        st.markdown("---")
        st.subheader("📊 Hasil Perhitungan Cryptographic Hash")
        
        st.write("**MD5 Hash:**")
        st.code(md5_hash, language="text")
        
        st.write("**SHA-1 Hash:**")
        st.code(sha1_hash, language="text")
        
        st.write("**SHA-256 Hash (Standar Keamanan Saat Ini):**")
        st.code(sha256_hash, language="text")

        st.markdown("---")
        st.subheader("🔍 Verifikasi Pembanding (Integrity Verification)")
        st.caption("Tempelkan hash resmi dari pembuat software / vendor di sini untuk mencocokkan keaslian berkas.")
        
        expected_hash = st.text_input("Masukkan Hash Pembanding / Hash Resmi Vendor:", placeholder="Contoh: a1b2c3d4...", key="input_expected_hash").strip().lower()

        if expected_hash:
            if expected_hash in [md5_hash, sha1_hash, sha256_hash]:
                st.success("✅ **INTEGRITAS TERVERIFIKASI!** Hash cocok. Berkas ini 100% asli dan belum pernah dimodifikasi.")
            else:
                st.error("❌ **INTEGRITAS TIDAK COCOK!** Hash berbeda. Berkas mungkin telah dimodifikasi, rusak (corrupt), atau telah disusupi kode berbahaya.")

# ==============================================================================
# MODUL 4: DNS SECURITY INSPECTOR
# ==============================================================================
with modul_dns:
    st.markdown("### 🔍 DNS Security Inspector")
    st.write("Periksa rekod DNS utama (A, MX, NS) serta keberadaan proteksi email tingkat domain (**SPF** & **DMARC**).")

    domain_input = st.text_input("Masukkan Nama Domain Target:", placeholder="contoh: google.com atau github.com", key="input_dns_domain").strip()
    btn_dns = st.button("🔍 Cek Rekod DNS", type="primary", key="btn_dns_check")

    if btn_dns and domain_input:
        # Bersihkan input dari http/https jika ketikan user ada URL-nya
        clean_domain = domain_input.replace("https://", "").replace("http://", "").split("/")[0]
        st.info(f"🔍 Mengambil data DNS untuk domain: `{clean_domain}`")

        import dns.resolver

        def fetch_dns(domain, rtype):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                return [str(rdata) for rdata in answers]
            except Exception:
                return []

        # Ambil Rekod DNS
        records_a = fetch_dns(clean_domain, 'A')
        records_mx = fetch_dns(clean_domain, 'MX')
        records_ns = fetch_dns(clean_domain, 'NS')
        records_txt = fetch_dns(clean_domain, 'TXT')
        records_dmarc = fetch_dns(f"_dmarc.{clean_domain}", 'TXT')

        tab_dns1, tab_dns2 = st.tabs(["📋 Rekod DNS Jaringan", "🔐 Keamanan Email Domain (SPF & DMARC)"])

        with tab_dns1:
            st.subheader("🌐 Informasi Alamat IP & Server Domain")
            col_dns1, col_dns2 = st.columns(2)
            
            with col_dns1:
                st.write("**A Records (IP Address Web Server):**")
                if records_a:
                    for ip in records_a:
                        st.code(ip, language="text")
                else:
                    st.warning("Tidak ditemukan rekod A.")

                st.write("**NS Records (Nameserver):**")
                if records_ns:
                    for ns in records_ns:
                        st.code(ns, language="text")
                else:
                    st.warning("Tidak ditemukan rekod NS.")

            with col_dns2:
                st.write("**MX Records (Mail Exchange Server):**")
                if records_mx:
                    for mx in records_mx:
                        st.code(mx, language="text")
                else:
                    st.warning("Tidak ditemukan rekod MX.")

        with tab_dns2:
            st.subheader("🛡️ Status Konfigurasi Keamanan Email")
            
            # Pengecekan SPF Record
            spf_found = [txt for txt in records_txt if "v=spf1" in txt]
            st.write("**SPF Record (Sender Policy Framework):**")
            if spf_found:
                st.success("✅ **SPF Ditemukan!** Domain ini membatasi IP server yang berhak mengirim email atas namaya.")
                for spf in spf_found:
                    st.code(spf, language="text")
            else:
                st.error("❌ **SPF Tidak Ditemukan!** Domain ini belum mempublikasikan daftar server email resminya.")

            st.markdown("---")

            # Pengecekan DMARC Record
            dmarc_found = [txt for txt in records_dmarc if "v=DMARC1" in txt]
            st.write("**DMARC Record (Policy Rule):**")
            if dmarc_found:
                st.success("✅ **DMARC Ditemukan!** Domain ini instruksikan server penerima untuk menolak email palsu.")
                for dmarc in dmarc_found:
                    st.code(dmarc, language="text")
            else:
                st.error("❌ **DMARC Tidak Ditemukan!** Domain tidak memiliki kebijakan perlindungan pemalsuan (*spoofing*).")                
                st.success("✅ **INTEGRITAS TERVERIFIKASI!** Hash cocok. Berkas ini 100% asli dan belum pernah dimodifikasi.")
            else:
                st.error("❌ **INTEGRITAS TIDAK COCOK!** Hash berbeda. Berkas mungkin telah dimodifikasi, rusak (corrupt), atau telah disusupi kode berbahaya.")
