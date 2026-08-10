# 🛡️ Blue Team Security Suite

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-Framework-FF4B4B.svg)
![Type](https://img.shields.io/badge/Security-Blue%20Team%20Defensive-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

# 🛡️ All-in-One SOC & Cybersecurity Operations Dashboard

Dashboard analisis keamanan siber interaktif berbasis **Streamlit** dan **Python**. Aplikasi ini dirancang untuk kebutuhan analisis insiden (*incident response*), investigasi jaringan, inspeksi privasi, hingga edukasi kesadaran keamanan (*security awareness*). Setiap modul dilengkapi dengan **Offline Simulation / Sample Mode** sehingga dapat diuji coba secara aman tanpa koneksi internet atau data sensitif.

---

## 🚀 Fitur & Modul Utama

Dashboard ini terdiri dari **10 Modul Keamanan**:

1. **🔐 Password Strength & Hash Generator** — Evaluasi keamanan kata sandi dan pembuatan cryptographic hash instan.
2. **🌐 Domain & IP Lookup** — Pemeriksaan awal entitas domain dan pengalamatan IP.
3. **🔑 File Hash & Integrity Checker** — Verifikasi integritas berkas (MD5, SHA-1, SHA-256) serta pengujian sampel malware EICAR.
4. **🔍 DNS Security Inspector** — Pemeriksaan rekod jaringan (A, MX, NS) dan proteksi *email anti-spoofing* (**SPF** & **DMARC**).
5. **🔐 Password Entropy & Crack Time Evaluator** — Kalkulasi matematis entropi ($E = L \times \log_2(R)$) dan estimasi waktu pembobolan *brute-force* offline.
6. **🔤 SOC Text & Payload Encoder / Decoder** — Konversi dwi-arah cepat untuk Base64, URL Encoding, Hexadecimal, dan HTML Entities.
7. **🖼️ EXIF Metadata Inspector & Sanitizer** — Deteksi koordinat GPS tersembunyi pada foto dan pembersihan (*sanitizing*) metadata instan.
8. **📡 Network Auto-Discovery & Port Sweeper** — Pemindaian subnet lokal otomatis dan pendeteksian port aktif (SSH, HTTP, RTSP, SMB).
9. **🗺️ IP Threat Intelligence & Geolocation Mapper** — Pemetaan lokasi fisik IP target, identifikasi ISP/ASN, serta penanda risiko (Proxy / VPN / TOR / Hosting).
10. **🛡️ Web Log Security Parser & Threat Hunter** — Parsing log akses web (Nginx / Apache) untuk perburuan ancaman SQLi, XSS, Path Traversal, dan Command Injection.

---

## 🛠️ Prasyarat & Dependensi

Pastikan Anda telah menginstal **Python 3.9+** pada sistem Anda. 

### Dependensi Library Python:
* `streamlit`
* `dnspython`
* `Pillow`
* `pandas`

---

## 📥 Instalasi & Jalankan Aplikasi

1. **Clone repository ini / unduh project folder:**
   ```bash
   git clone [https://github.com/username/soc-cybersecurity-dashboard.git](https://github.com/username/soc-cybersecurity-dashboard.git)
   cd soc-cybersecurity-dashboard
