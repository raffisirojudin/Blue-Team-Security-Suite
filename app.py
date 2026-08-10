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
import hashlib
import dns.resolver

# Konfigurasi Halaman Web
st.set_page_config(page_title="Blue Team Security Suite", page_icon="🛡️", layout="wide")

st.title("🛡️ Blue Team Security Suite")
st.caption("Platform analisis keamanan defensif terpadu untuk pengujian Email Phishing, Audit Web/SSL, Integritas Hash, dan Rekod DNS.")

# Navigasi Modul Utama (Top Tabs)
modul_email, modul_web, modul_hash, modul_dns, modul_pwd, modul_encode, modul_exif, modul_network, modul_threat, modul_log = st.tabs([
    "📧 Modul 1: Email Header & Phishing Analyzer", 
    "🌐 Modul 2: Website Security Headers & SSL Auditor",
    "🔑 Modul 3: File Hash & Integrity Checker",
    "🔍 Modul 4: DNS Security Inspector",
    "🔐 Modul 5: Password Entropy Evaluator",
    "🔤 Modul 6: SOC Text & Payload Encoder / Decoder",
    "🖼️ Modul 7: EXIF Metadata Inspector & Sanitizer",
    "📡 Modul 8: Network Auto-Discovery & Port Sweeper",
    "🗺️ Modul 9: IP Threat Intelligence & Geolocation",
    "🛡️ Modul 10: Web Log Security Parser & Threat Hunter"
])

# ==============================================================================
# MODUL 1: EMAIL HEADER & PHISHING ANALYZER
# ==============================================================================
with modul_email:
    st.markdown("### 📧 Email Header & Phishing Analyzer")
    st.write("Analisis file `.eml` atau *raw header* email untuk memeriksa otentikasi pengirim dan tautan berbahaya.")

    import textwrap

    st.sidebar.header("📥 Input Email")
    mode_input = st.sidebar.radio("Pilih Cara Unggah Email:", ["File .EML", "Tempel Raw Header (Teks)"], key="mode_email_input")

    raw_email_obj = None

    if mode_input == "File .EML":
        uploaded_eml = st.file_uploader("Unggah file email (.eml):", type=['eml'], key="uploader_eml")
        if uploaded_eml:
            raw_email_obj = BytesParser(policy=policy.default).parse(uploaded_eml)
    else:
        use_sample_email = st.checkbox("Gunakan Sample Header Email Phishing Simulasi", key="chk_sample_email")
        
        sample_header_text = textwrap.dedent("""\
            Received: from mail.suspicious-bank-update.com (mail.suspicious-bank-update.com [185.220.101.5])
                by mx.google.com with ESMTPS id x123456789
                for <victim@company.com>; Mon, 10 Aug 2026 10:15:30 -0700
            Authentication-Results: mx.google.com;
                spf=softfail (google.com: domain of transition may not designate 185.220.101.5 as permitted sender) smtp.mailfrom=admin@suspicious-bank-update.com;
                dkim=fail header.i=@suspicious-bank-update.com;
                dmarc=fail (p=REJECT) action=none header.from=suspicious-bank-update.com;
            From: "Bank Security Alert" <admin@suspicious-bank-update.com>
            To: victim@company.com
            Reply-To: attacker-box@phishing-server.ru
            Subject: URGENT: Akun Anda Dibekukan! Segera Verifikasi Data Anda
            Date: Mon, 10 Aug 2026 10:15:00 -0700
            Content-Type: text/html; charset="UTF-8"

            <html>
            <body>
            <p>Silakan amankan akun Anda melalui tautan resmi kami:</p>
            <a href="http://185.220.101.5/login-phishing">https://bankresmi.co.id/login</a>
            </body>
            </html>
        """)

        if use_sample_email:
            header_text = st.text_area("Tempelkan Raw Header / Teks Email di sini:", value=sample_header_text, height=220, key="area_eml_text_sample")
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
            st.error(f"❌ Gagal menghubungi situs target: `{http_error}`.")
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
                    st.success("🎉 Tidak ada kebocoran header versi server terdeteksi.")

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
        clean_domain = domain_input.replace("https://", "").replace("http://", "").split("/")[0]
        st.info(f"🔍 Mengambil data DNS untuk domain: `{clean_domain}`")

        def fetch_dns(domain, rtype):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                return [str(rdata) for rdata in answers]
            except Exception:
                return []

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
            
            spf_found = [txt for txt in records_txt if "v=spf1" in txt]
            st.write("**SPF Record (Sender Policy Framework):**")
            if spf_found:
                st.success("✅ **SPF Ditemukan!** Domain ini membatasi IP server yang berhak mengirim email atas namaya.")
                for spf in spf_found:
                    st.code(spf, language="text")
            else:
                st.error("❌ **SPF Tidak Ditemukan!** Domain ini belum mempublikasikan daftar server email resminya.")

            st.markdown("---")

            dmarc_found = [txt for txt in records_dmarc if "v=DMARC1" in txt]
            st.write("**DMARC Record (Policy Rule):**")
            if dmarc_found:
                st.success("✅ **DMARC Ditemukan!** Domain ini menginstruksikan server penerima untuk menolak email palsu.")
                for dmarc in dmarc_found:
                    st.code(dmarc, language="text")
            else:
                st.error("❌ **DMARC Tidak Ditemukan!** Domain tidak memiliki kebijakan perlindungan pemalsuan (*spoofing*).")

# ==============================================================================
# MODUL 5: PASSWORD ENTROPY & CRACK TIME EVALUATOR
# ==============================================================================
with modul_pwd:
    st.markdown("### 🔐 Password Entropy & Crack Time Evaluator")
    st.write("Evaluasi kekuatan kata sandi menggunakan rumus matematis **Bit Entropy** ($E = L \\times \\log_2(R)$) serta estimasi waktu *brute-force*.")

    col_p1, col_p2 = st.columns([2, 1])
    with col_p1:
        pwd_input = st.text_input("Masukkan Kata Sandi yang Ingin Diuji:", type="password", key="input_password_eval").strip()
    with col_p2:
        st.write("")
        st.write("")
        show_pwd = st.checkbox("Tampilkan Teks Kata Sandi", key="chk_show_pwd")

    if show_pwd and pwd_input:
        st.info(f"Teks Kata Sandi: `{pwd_input}`")

    if pwd_input:
        import math

        # Hitung Variasi Karakter (Pool Size - R)
        has_lower = bool(re.search(r'[a-z]', pwd_input))
        has_upper = bool(re.search(r'[A-Z]', pwd_input))
        has_digit = bool(re.search(r'\d', pwd_input))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', pwd_input))

        pool_size = 0
        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_symbol: pool_size += 32

        pwd_len = len(pwd_input)
        
        # Hitung Entropi (E = L * log2(R))
        entropy = pwd_len * math.log2(pool_size) if pool_size > 0 else 0

        # Estimasi Waktu Crack (Asumsi Hashcat GPU Rig Modern: 100 Miliar Guesses/Detik)
        guesses_per_sec = 100_000_000_000
        total_combinations = pool_size ** pwd_len if pool_size > 0 else 0
        avg_attempts = total_combinations / 2
        seconds_to_crack = avg_attempts / guesses_per_sec if guesses_per_sec > 0 else 0

        # Format Tampilan Waktu
        def format_crack_time(seconds):
            if seconds < 1:
                return "Instan (< 1 detik)"
            minutes = seconds / 60
            hours = minutes / 60
            days = hours / 24
            years = days / 365
            if years > 1_000_000:
                return f"{years/1_000_000:,.1f} Juta Tahun"
            elif years >= 1:
                return f"{years:,.1f} Tahun"
            elif days >= 1:
                return f"{days:,.1f} Hari"
            elif hours >= 1:
                return f"{hours:,.1f} Jam"
            elif minutes >= 1:
                return f"{minutes:,.1f} Menit"
            else:
                return f"{seconds:,.1f} Detik"

        crack_time_str = format_crack_time(seconds_to_crack)

        # Penilaian Kekuatan
        if entropy < 40:
            status_label = "Sangat Lemah"
            status_color = "red"
        elif entropy < 60:
            status_label = "Sedang / Rentan"
            status_color = "orange"
        elif entropy < 80:
            status_label = "Kuat"
            status_color = "green"
        else:
            status_label = "Sangat Kuat (Sangat Aman)"
            status_color = "blue"

        st.markdown("---")
        st.subheader("📊 Hasil Evaluasi Kekuatan")

        col_m1, col_m2, col_m3 = st.columns(3)
        col_m1.metric("Panjang Karakter (L)", f"{pwd_len} Karakter")
        col_m2.metric("Skor Entropi", f"{entropy:.1f} bits")
        col_m3.metric("Kategori Kekuatan", status_label)

        st.write(f"⏱️ **Estimasi Waktu Brute-Force (Offline GPU Rig):** `{crack_time_str}`")

        st.markdown("---")
        st.subheader("📋 Analisis Variasi Karakter")
        col_c1, col_c2, col_c3, col_c4 = st.columns(4)
        col_c1.write(f"{'✅' if has_lower else '❌'} Huruf Kecil (a-z)")
        col_c2.write(f"{'✅' if has_upper else '❌'} Huruf Besar (A-Z)")
        col_c3.write(f"{'✅' if has_digit else '❌'} Angka (0-9)")
        col_c4.write(f"{'✅' if has_symbol else '❌'} Simbol / Karakter Khusus")

        # Rekomendasi Keamanan
        if entropy < 60:
            st.warning("⚠️ **Saran Perbaikan:** Tambahkan panjang kata sandi menjadi minimal 12–16 karakter dan kombinasikan huruf besar, angka, serta simbol khusus untuk meningkatkan bit entropi secara drastis.")
        else:
            st.success("🎉 Kata sandi ini memiliki variasi dan panjang yang sangat baik terhadap serangan *Brute-Force* offline!")

# ==============================================================================
# MODUL 6: SOC TEXT & PAYLOAD ENCODER / DECODER
# ==============================================================================
with modul_encode:
    st.markdown("### 🔤 SOC Text & Payload Encoder / Decoder")
    st.write("Lakukan konversi, enkoding, atau dekoding *payload* / *string* terselubung secara cepat untuk kebutuhan analisis insiden siber.")

    import base64
    import urllib.parse
    import html

    col_e1, col_e2 = st.columns([1, 2])
    
    with col_e1:
        metode = st.selectbox(
            "Pilih Format / Metode Konversi:",
            ["Base64", "URL Encoding (Percent-encoding)", "Hexadecimal (Hex)", "HTML Entities"],
            key="select_encode_method"
        )
        aksi = st.radio(
            "Pilih Operasi:",
            ["Decode (Dekode / Terjemahkan)", "Encode (Enkode / Acak)"],
            key="radio_encode_action"
        )

    with col_e2:
        input_text = st.text_area(
            "Masukkan Teks / Payload Target di Sini:",
            height=150,
            placeholder="Contoh Base64: aHR0cHM6Ly9tYWxpY2lvdXMuc2l0ZQ==\nContoh Hex: 48656c6c6f",
            key="area_encode_input"
        ).strip()

    if input_text:
        hasil = ""
        error_msg = None

        try:
            if aksi == "Decode (Dekode / Terjemahkan)":
                if metode == "Base64":
                    # Menangani padding base64 jika kurang
                    padded_input = input_text + '=' * (-len(input_text) % 4)
                    hasil = base64.b64decode(padded_input.encode()).decode('utf-8', errors='ignore')
                elif metode == "URL Encoding (Percent-encoding)":
                    hasil = urllib.parse.unquote(input_text)
                elif metode == "Hexadecimal (Hex)":
                    clean_hex = input_text.replace(" ", "").replace("0x", "").replace("\\x", "").replace("\n", "")
                    hasil = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
                elif metode == "HTML Entities":
                    hasil = html.unescape(input_text)
            else: # Encode
                if metode == "Base64":
                    hasil = base64.b64encode(input_text.encode()).decode('utf-8')
                elif metode == "URL Encoding (Percent-encoding)":
                    hasil = urllib.parse.quote(input_text)
                elif metode == "Hexadecimal (Hex)":
                    hasil = input_text.encode().hex()
                elif metode == "HTML Entities":
                    hasil = html.escape(input_text)
        except Exception as e:
            error_msg = str(e)

        st.markdown("---")
        st.subheader("📤 Hasil Output Operations")

        if error_msg:
            st.error(f"❌ **Gagal Memproses Data!** Pastikan format teks input sesuai untuk metode `{metode}`. Detail Error: `{error_msg}`")
        else:
            st.code(hasil, language="text")
            st.success("✅ Proses konversi berhasil diselesaikan!")

# ==============================================================================
# MODUL 7: EXIF METADATA INSPECTOR & SANITIZER
# ==============================================================================
with modul_exif:
    st.markdown("### 🖼️ EXIF Metadata Inspector & Sanitizer")
    st.write("Deteksi lokasi GPS tersembunyi, informasi perangkat, dan bersihkan metadata foto demi menjaga privasi.")

    from PIL import Image
    from PIL.ExifTags import TAGS
    import io

    uploaded_img = st.file_uploader("Unggah Foto (JPG / JPEG / PNG):", type=["jpg", "jpeg", "png"], key="uploader_exif")

    if uploaded_img:
        image = Image.open(uploaded_img)
        
        col_img1, col_img2 = st.columns([1, 1])
        with col_img1:
            st.image(image, caption="Foto Target", use_container_width=True)

        with col_img2:
            st.subheader("🔍 Metadata Terdeteksi")
            
            exif_data = image._getexif() if hasattr(image, '_getexif') else None
            parsed_exif = {}

            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    parsed_exif[tag_name] = value

                # Tampilkan Informasi Kunci
                st.write(f"**Merek Perangkat:** `{parsed_exif.get('Make') or 'Tidak ada'}`")
                st.write(f"**Model Perangkat:** `{parsed_exif.get('Model') or 'Tidak ada'}`")
                st.write(f"**Waktu Pengambilan:** `{parsed_exif.get('DateTimeOriginal') or 'Tidak ada'}`")
                st.write(f"**Software/OS:** `{parsed_exif.get('Software') or 'Tidak ada'}`")

                # Cek Adanya GPS
                if 'GPSInfo' in parsed_exif:
                    st.error("🚨 **DETEKSI LOKASI GPS!** Foto ini mengandung koordinat lokasi fisik pengambilan gambar.")
                else:
                    st.success("✅ Tidak ditemukan data lokasi GPS pada berkas ini.")
            else:
                st.info("ℹ️ Foto ini tidak mengandung metadata EXIF (mungkin sudah dibersihkan atau diunggah dari aplikasi yang menghapus EXIF).")

        st.markdown("---")
        st.subheader("🛡️ Pembersihan Metadata (Sanitizing)")
        
        # Proses Pembersihan Metadata & Konversi Mode Gambar
        clean_image = image.convert("RGB")

        # Simpan ke buffer memori untuk diunduh
        buf = io.BytesIO()
        clean_image.save(buf, format="JPEG")
        byte_im = buf.getvalue()

        st.download_button(label="⬇️ Unduh Foto Steril (Tanpa Metadata)", data=byte_im, file_name=f"steril_{uploaded_img.name}", mime="image/jpeg", type="primary")
# ==============================================================================
# MODUL 8: NETWORK AUTO-DISCOVERY & PORT SWEEPER
# ==============================================================================
with modul_network:
    st.markdown("### 📡 Network Auto-Discovery & Port Sweeper")
    st.write("Temukan IP publik ISP, IP router Wi-Fi, dan perangkat lokal tanpa perlu masuk ke admin router.")

    import socket
    import urllib.request
    import json
    from concurrent.futures import ThreadPoolExecutor
    import pandas as pd

    # --- FUNGSI DENGAN MULTI-API FALLBACK ---
    def dapatkan_info_jaringan():
        pub_ip, isp_name, local_ip = "Tidak diketahui", "Tidak diketahui", "127.0.0.1"
        
        # 1. Ambil IP Lokal Perangkat
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            pass

        # 2. Ambil IP Publik & ISP (Otomatis berpindah API jika salah satu limit)
        try:
            # Jalur Utama: ip-api.com
            req = urllib.request.Request("http://ip-api.com/json/", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=4) as response:
                data = json.loads(response.read().decode())
                pub_ip = data.get("query", "Tidak diketahui")
                isp_name = data.get("isp", data.get("org", "Tidak diketahui"))
        except:
            try:
                # Cadangan: ipify.org
                with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=4) as resp:
                    pub_ip = json.loads(resp.read().decode()).get("ip", "Tidak diketahui")
                    isp_name = "Terhubung Internet"
            except:
                pass

        return pub_ip, isp_name, local_ip

    # Tampilkan Informasi IP & ISP
    pub_ip, isp_name, local_ip = dapatkan_info_jaringan()

    # Ekstraksi otomatis prefix subnet lokal (misal: "10.16.15.41" -> "10.16.15.")
    default_prefix = ".".join(local_ip.split(".")[:-1]) + "." if "." in local_ip else "192.168.1."

    st.markdown("##### ℹ️ Informasi Koneksi Wi-Fi / Internet Anda")
    col_info1, col_info2, col_info3 = st.columns(3)
    with col_info1:
        st.metric("🌐 IP Publik (Dari ISP)", pub_ip)
    with col_info2:
        st.metric("🏢 Penyedia ISP", isp_name)
    with col_info3:
        st.metric("💻 IP Lokal Perangkat Ini", local_ip)

    st.divider()

    col_net1, col_net2 = st.columns([1, 1])

    with col_net1:
        subnet_prefix = st.text_input("Subnet IP Target (Prefix):", value=default_prefix, help="Otomatis terisi berdasarkan IP lokal Anda.")
        range_ip = st.slider("Rentang IP (Host Range):", 1, 254, (1, 100))

    with col_net2:
        ports_to_scan = st.multiselect(
            "Port yang Dipindai:",
            options=[22, 80, 443, 1900, 5353, 8080, 9100, 554, 445],
            default=[22, 80, 443, 8080],
            format_func=lambda x: {
                22: "22 (SSH - Raspberry Pi / Linux)",
                80: "80 (HTTP - Router / Smart TV / Printer)",
                443: "443 (HTTPS - Web Secure)",
                1900: "1900 (UPnP - Smart TV / Chromecast)",
                5353: "5353 (mDNS - AirPlay / Apple / Wi-Fi Device)",
                8080: "8080 (Web UI Alternatif)",
                9100: "9100 (RAW Printer Wi-Fi)",
                554: "554 (RTSP - IP Camera / CCTV)",
                445: "445 (SMB - Windows Share / NAS)"
            }.get(x, str(x))
        )

    def ping_host_port(target):
        ip, port = target
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return (ip, port)
        except:
            pass
        return None

    if st.button("🚀 Mulai Pemindaian Jaringan", type="primary"):
        if not ports_to_scan:
            st.warning("⚠️ Pilih minimal satu port untuk dipindai.")
        else:
            ip_targets = [f"{subnet_prefix}{i}" for i in range(range_ip[0], range_ip[1] + 1)]
            scan_list = [(ip, port) for ip in ip_targets for port in ports_to_scan]

            total_scans = len(scan_list)
            st.write(f"🔍 Memindai **{len(ip_targets)} IP** pada **{len(ports_to_scan)} port** (Total {total_scans} cek)...")
            
            progress_bar = st.progress(0)
            found_devices = []

            with ThreadPoolExecutor(max_workers=100) as executor:
                for idx, res in enumerate(executor.map(ping_host_port, scan_list)):
                    progress_bar.progress((idx + 1) / total_scans)
                    if res:
                        ip_found, port_found = res
                        estimasi = {
                            22: "Raspberry Pi / Linux Server / SSH",
                            80: "Router Admin / Smart TV / Web Device",
                            443: "Secure Web Interface",
                            1900: "Smart TV / Chromecast / UPnP Device",
                            5353: "Apple / mDNS / Wi-Fi Smart Home",
                            8080: "Web Dashboard / Proxy",
                            9100: "Printer Wi-Fi / Network Printer",
                            554: "IP Camera / CCTV",
                            445: "NAS / Windows Share / Printer"
                        }.get(port_found, "Perangkat Aktif")
                        
                        found_devices.append({
                            "Alamat IP": ip_found,
                            "Port Terbuka": port_found,
                            "Estimasi Jenis Perangkat": estimasi,
                            "Akses Web": f"http://{ip_found}:{port_found}" if port_found in [80, 8080] else "N/A"
                        })

            progress_bar.empty()

            if found_devices:
                st.success(f"✅ Pemindaian selesai! Ditemukan **{len(found_devices)}** layanan aktif.")
                df_res = pd.DataFrame(found_devices)
                st.dataframe(df_res, use_container_width=True)
            else:
                st.warning("❌ Tidak ada perangkat aktif yang merespons pada subnet dan port yang dipilih.")

# ==============================================================================
# MODUL 9: IP THREAT INTELLIGENCE & GEOLOCATION MAPPER
# ==============================================================================
with modul_threat:
    st.markdown("### 🗺️ IP Threat Intelligence & Geolocation Mapper")
    st.write("Investigasi lokasi fisik IP mencurigakan, ISP/ASN penanggung jawab, serta deteksi penggunaan Proxy/VPN.")

    import urllib.request
    import json
    import pandas as pd

    target_ip = st.text_input("Masukkan Alamat IP Target (IPv4 / IPv6):", value="8.8.8.8", help="Masukkan IP publik yang ingin diinvestigasi.")

    if st.button("🔍 Investigasi IP", type="primary"):
        if not target_ip.strip():
            st.warning("⚠️ Masukkan alamat IP yang valid.")
        else:
            try:
                # Mengambil data intelijen IP dari API
                url = f"http://ip-api.com/json/{target_ip.strip()}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())

                if data.get("status") == "fail":
                    st.error(f"❌ Gagal memproses IP: {data.get('message', 'IP tidak valid/publik')}")
                else:
                    col_t1, col_t2, col_t3, col_t4 = st.columns(4)
                    with col_t1:
                        st.metric("🏳️ Negara", f"{data.get('country')} ({data.get('countryCode')})")
                    with col_t2:
                        st.metric("🏙️ Kota", data.get('city', 'N/A'))
                    with col_t3:
                        st.metric("🏢 Penyedia ISP", data.get('isp', 'N/A'))
                    with col_t4:
                        st.metric("🌐 ASN / Org", data.get('as', 'N/A').split()[0])

                    st.divider()

                    # Menampilkan Peta Interaktif
                    lat = data.get("lat")
                    lon = data.get("lon")
                    if lat and lon:
                        st.markdown("##### 📍 Peta Lokasi Server IP")
                        map_data = pd.DataFrame({'lat': [lat], 'lon': [lon]})
                        st.map(map_data, zoom=10)

                    # Indikator Risiko / Threat Check
                    st.markdown("##### ⚠️ Indikator Potensi Risiko")
                    is_proxy = data.get("proxy", False)
                    is_hosting = data.get("hosting", False)

                    col_r1, col_r2 = st.columns(2)
                    with col_r1:
                        if is_proxy:
                            st.error("🚫 **Proxy / VPN / TOR Detected:** IP ini teridentifikasi sebagai node perantara.")
                        else:
                            st.success("✅ **Bukan Proxy / VPN:** Alamat IP tercatat sebagai IP perumahan/koneksi standar.")
                    
                    with col_r2:
                        if is_hosting:
                            st.warning("⚠️ **Data Center / Hosting:** IP ini berasal dari server cloud/hosting, bukan perangkat seluler/rumah pengguna.")
                        else:
                            st.info("ℹ️ **Residential / ISP:** IP ini dialokasikan untuk pengguna akhir (End-User).")

            except Exception as e:
                st.error(f"❌ Terjadi kesalahan saat menghubungkan ke server intelijen: {e}")

# ==============================================================================
# MODUL 10: WEB LOG SECURITY PARSER & THREAT HUNTER
# ==============================================================================
with modul_log:
    st.markdown("### 🛡️ Web Log Security Parser & Threat Hunter")
    st.write("Unggah file log akses web (Nginx / Apache) untuk mendeteksi serangan SQL Injection, XSS, Path Traversal, dan Brute Force secara otomatis.")

    import re
    import pandas as pd

    uploaded_log = st.file_uploader("Unggah File Log (.log / .txt):", type=["log", "txt"])
    sample_log_button = st.checkbox("Gunakan Sample Log Simulasi Serangan")

    log_content = ""
    if uploaded_log is not None:
        log_content = uploaded_log.getvalue().decode("utf-8", errors="ignore")
    elif sample_log_button:
        log_content = """192.168.1.50 - - [10/Aug/2026:10:00:01 +0000] "GET /index.php HTTP/1.1" 200 1450
10.0.0.12 - - [10/Aug/2026:10:01:15 +0000] "GET /admin/login.php?user=admin' OR 1=1-- HTTP/1.1" 200 4200
172.16.0.4 - - [10/Aug/2026:10:02:30 +0000] "GET /search?q=<script>alert('XSS')</script> HTTP/1.1" 200 2300
192.168.1.100 - - [10/Aug/2026:10:03:00 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 230
10.0.0.12 - - [10/Aug/2026:10:04:12 +0000] "POST /login.php HTTP/1.1" 401 512
10.0.0.12 - - [10/Aug/2026:10:04:13 +0000] "POST /login.php HTTP/1.1" 401 512
10.0.0.12 - - [10/Aug/2026:10:04:14 +0000] "POST /login.php HTTP/1.1" 401 512
45.33.32.156 - - [10/Aug/2026:10:05:22 +0000] "GET /shell.php;id;whoami HTTP/1.1" 404 180"""

    if log_content:
        lines = log_content.strip().split("\n")
        st.info(f"📊 Memproses total **{len(lines)}** baris log...")

        # Pattern Regex Log Standar Apache/Nginx
        log_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<time>.*?)\] "(?P<method>\w+) (?P<url>\S+) (?P<proto>\S+)" (?P<status>\d+) (?P<bytes>\d+|-)'
        )

        parsed_logs = []
        threats_found = []

        # Kamus Deteksi Payload Serangan
        attack_signatures = {
            "SQL Injection (SQLi)": r"(?i)(SELECT|UNION|INSERT|DELETE|OR\s+1=1|'|--|INFORMATION_SCHEMA)",
            "Cross-Site Scripting (XSS)": r"(?i)(<script>|javascript:|onload=|alert\(|<img)",
            "Path Traversal (LFI/RFI)": r"(?i)(\.\./|\.\.\\|/etc/passwd|boot\.ini)",
            "Command Injection": r"(?i)(;|&&|\|\||cmd\.exe|/bin/bash|whoami|id\b)"
        }

        for line in lines:
            match = log_pattern.match(line)
            if match:
                data = match.groupdict()
                parsed_logs.append(data)
                
                # Cek Payload Serangan
                url_requested = data["url"]
                detected_types = []
                for attack_name, pattern in attack_signatures.items():
                    if re.search(pattern, url_requested):
                        detected_types.append(attack_name)
                
                if detected_types:
                    data_threat = data.copy()
                    data_threat["Kategori Serangan"] = ", ".join(detected_types)
                    threats_found.append(data_threat)

        df_logs = pd.DataFrame(parsed_logs)
        df_threats = pd.DataFrame(threats_found)

        col_l1, col_l2, col_l3 = st.columns(3)
        with col_l1:
            st.metric("📥 Total Request", len(parsed_logs))
        with col_l2:
            st.metric("⚠️ Ancaman Terdeteksi", len(threats_found))
        with col_l3:
            top_ip = df_logs["ip"].mode()[0] if not df_logs.empty else "N/A"
            st.metric("🔥 IP Teraktif", top_ip)

        st.divider()

        if not df_threats.empty:
            st.error(f"🚨 **Ditemukan {len(df_threats)} Aktivitas Mencurigakan / Serangan Web!**")
            st.dataframe(df_threats[["ip", "time", "method", "url", "status", "Kategori Serangan"]], use_container_width=True)
        else:
            st.success("✅ Tidak terdeteksi indikasi serangan web populer pada file log ini.")

        if not df_logs.empty:
            st.markdown("##### 📈 Distribusi HTTP Status Code")
            status_counts = df_logs["status"].value_counts()
            st.bar_chart(status_counts)
