# 🛡️ Blue Team Security Suite

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-Framework-FF4B4B.svg)
![Type](https://img.shields.io/badge/Security-Blue%20Team%20Defensive-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**Blue Team Security Suite** adalah platform analisis keamanan defensif (*Cybersecurity Defensive Platform*) terpadu berbasis web yang dibangun menggunakan **Python** dan **Streamlit**. 

Platform ini dirancang untuk membantu analis *Security Operations Center* (SOC), *SysAdmin*, maupun praktisi keamanan siber dalam mengaudit, menguji, dan menganalisis potensi ancaman keamanan digital dengan cepat dan efisien dalam satu antarmuka antarmuka yang ramah pengguna.

---

## 🚀 Fitur Utama & Modul Keamanan

Platform ini terdiri dari **6 Modul Defensif Utama**:

| Modul | Nama Fitur | Deskripsi Singkat |
| :--- | :--- | :--- |
| **Modul 1** | 📧 Email Header & Phishing Analyzer | Analisis file `.eml` / *raw header* untuk deteksi pemalsuan pengirim & tautan *phishing*. |
| **Modul 2** | 🌐 Website Security Headers & SSL Auditor | Audit konfigurasi *HTTP Security Headers* dan validitas sertifikat SSL/TLS domain. |
| **Modul 3** | 🔑 File Hash & Integrity Checker | Perhitungan *cryptographic hash* (MD5, SHA-1, SHA-256) & verifikasi integritas berkas. |
| **Modul 4** | 🔍 DNS Security Inspector | Inspeksi rekod DNS (A, MX, NS) dan validasi proteksi email domain (SPF & DMARC). |
| **Modul 5** | 🔐 Password Entropy Evaluator | Penilaian kekuatan kata sandi berbasis *Bit Entropy* & estimasi waktu retas *brute-force*. |
| **Modul 6** | 🔤 SOC Text & Payload Encoder / Decoder | Konversi instan *payload* terselubung (Base64, Hex, URL-encoding, HTML Entities). |

---

## 📖 Detail Cara Kerja, Penggunaan, & Manfaat Modul

### 📧 1. Email Header & Phishing Analyzer
* **Cara Kerja:** Menganalisis metadata *Header* email untuk memvalidasi otentikasi pengirim (SPF, DKIM, DMARC), melacak rute transit server (*Hops*), serta mendeteksi *mismatch* antara teks visual tautan dan URL tujuan asli.
* **Cara Penggunaan:** Unggah berkas `.eml` atau tempelkan teks *raw header* email. Buka tab analisis untuk melihat status validasi otentikasi dan daftar tautan tersembunyi.
* **Manfaat:** Mencegah insiden *phishing* dan *email spoofing* sebelum pengguna mengklik tautan berbahaya.

### 🌐 2. Website Security Headers & SSL Auditor
* **Cara Kerja:** Memeriksa respons *HTTP Headers* dari domain target terhadap standar *security headers* (HSTS, CSP, X-Frame-Options, dll.), mendeteksi kebocoran versi server, dan mengevaluasi masa berlaku sertifikat SSL/TLS.
* **Cara Penggunaan:** Masukkan URL/domain target dan klik **Audit Keamanan Web**. Platform akan memberikan penilaian *Grade* (A+ hingga F) serta menyediaka kode rekomendasi konfigurasi Nginx.
* **Manfaat:** Membantu administrator server menutup celah keamanan web seperti *Clickjacking* dan *XSS*.

### 🔑 3. File Hash & Integrity Checker
* **Cara Kerja:** Menghitung sidik jari digital (*cryptographic hash*) dari berkas yang diunggah secara instan di memori tanpa menyimpan berkas ke server.
* **Cara Penggunaan:** Unggah berkas apapun (PDF, EXE, ZIP, Gambar, dll.), lalu tempelkan nilai hash resmi dari vendor pada kolom pembanding untuk memverifikasi keasliannya (`✅ MATCH` / `❌ MISMATCH`).
* **Manfaat:** Memastikan berkas yang diunduh bebas dari modifikasi atau sisipan *malware* (*file tampering*).

### 🔍 4. DNS Security Inspector
* **Cara Kerja:** Melakukan kueri DNS secara *real-time* untuk mengambil rekod jaringan (A, MX, NS) dan memeriksa konfigurasi rekod TXT untuk perlindungan pemalsuan email (SPF & DMARC).
* **Cara Penggunaan:** Masukkan nama domain target dan klik **Cek Rekod DNS** untuk melihat pemetaan infrastruktur dan status proteksi domain.
* **Manfaat:** Memberikan gambaran ketersediaan infrastruktur domain serta memastikan domain terlindungi dari aksi penipuan identitas.

### 🔐 5. Password Entropy Evaluator
* **Cara Kerja:** Menghitung nilai matematis kombinasi karakter (*Bit Entropy*: $E = L \times \log_2(R)$) dan mengestimasi waktu pemecahan kata sandi oleh komputer *brute-force* offline (GPU rig).
* **Cara Penggunaan:** Masukkan kata sandi yang ingin diuji untuk melihat skor bit entropi, variasi karakter, dan estimasi waktu retasnya.
* **Manfaat:** Mengedukasi pengguna untuk membuat kata sandi yang kuat dan tahan terhadap serangan *Brute-Force*.

### 🔤 6. SOC Text & Payload Encoder / Decoder
* **Cara Kerja:** Menerjemahkan atau mengacak *string/payload* terselubung menggunakan algoritma enkode/dekode umum (Base64, Hexadecimal, URL-encoding, dan HTML Entities).
* **Cara Penggunaan:** Pilih metode konversi dan aksi (Encode/Decode), lalu masukkan teks target untuk mendapatkan hasil output secara instan.
* **Manfaat:** Mempercepat tugas analisis SOC dalam membaca kode atau tautan berbahaya yang diacak (*obfuscated*) oleh peretas.

---

## 🛠️ Panduan Instalasi Lokal

Untuk menjalankan platform ini di komputer lokal Anda:

1. **Clone Repositori:**
   ```bash
   git clone [https://github.com/USERNAME_ANDA/blue-team-security-suite.git](https://github.com/USERNAME_ANDA/blue-team-security-suite.git)
   cd blue-team-security-suite
