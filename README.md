# 🛡️ Blue Team Security Suite

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-Framework-FF4B4B.svg)
![Type](https://img.shields.io/badge/Security-Blue%20Team%20Defensive-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Platform keamanan siber berbasis **Streamlit** dan **Python** yang menggabungkan dua alat analisis defensif utama untuk membantu praktisi *Blue Team* dan analis *Security Operations Center (SOC)*.

---

## ✨ Fitur Utama Platform

### 📧 1. Email Header & Phishing Analyzer
* **Ekstraksi Metadata & Spoofing Alert:** Menganalisis header `.eml` dan memberi peringatan jika alamat `Reply-To` tidak cocok dengan `From`.
* **Validasi Otentikasi Email:** Mengecek status **SPF**, **DKIM**, dan **DMARC**.
* **Pelacakan Received Hops:** Mengurutkan jejak server transit email.
* **Link Mismatch Detection:** Menandai tautan jika teks visual link berbeda dari URL tujuan sebenarnya.

### 🌐 2. Website Security Headers & SSL Auditor
* **Audit HTTP Security Headers:** Menilai keberadaan `HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, dll.
* **Sertifikat SSL/TLS Inspector:** Mengecek versi TLS, tanggal kedaluwarsa, dan penerbit (*Issuer*) sertifikat.
* **Information Disclosure Check:** Mendeteksi kebocoran versi web server pada header HTTP.
* **Panduan Perbaikan:** Menyediakan kode snippet untuk **Nginx**, **Apache**, dan **Cloudflare**.

---

## 🚀 Panduan Penggunaan Online

Aplikasi ini dapat diakses secara langsung tanpa instalasi lokal melalui **Streamlit Community Cloud**.

### Menjalankan Secara Lokal (Opsional)
```bash
# 1. Clone Repositori
git clone [https://github.com/USERNAME-ANDA/blue-team-security-suite.git](https://github.com/USERNAME-ANDA/blue-team-security-suite.git)
cd blue-team-security-suite

# 2. Install Library
pip install -r requirements.txt

# 3. Jalankan App
streamlit run app.py
