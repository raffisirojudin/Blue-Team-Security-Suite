# 🛡️ Email Header & Phishing Analyzer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-Framework-FF4B4B.svg)
![Focus](https://img.shields.io/badge/Focus-Defensive%20Cybersecurity-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Aplikasi web interaktif berbasis **Streamlit** dan **Python** yang dirancang untuk membantu analis keamanan (*Security Operations Center / SOC*) dan pengguna umum dalam mengevaluasi keaslian email, mendeteksi manipulasi *header*, serta mengidentifikasi indikasi serangan *phishing* secara cepat dan aman.

Aplikasi ini bekerja **100% secara lokal** (*offline-ready*), sehingga data sensitif atau isi email tidak pernah dikirim ke server pihak ketiga.

---

## ✨ Fitur Utama

- 📧 **Analisis Header Email (`.eml` / Raw Text):**
  - Ekstraksi otomatis metadata penting (`From`, `To`, `Reply-To`, `Subject`, `Date`, `Message-ID`).
  - **Deteksi Spoofing:** Membandingkan alamat `Reply-To` dan `From` untuk mendeteksi potensi pengalihan jawaban email (*mismatch warning*).
- 🔑 **Validasi Otentikasi Email:**
  - Pengecekan status **SPF** (*Sender Policy Framework*).
  - Pengecekan status **DKIM** (*DomainKeys Identified Mail*).
  - Pengecekan status **DMARC** (*Domain-based Message Authentication*).
- 🛤️ **Pelacakan Rute Transit (Received Hops):**
  - Merekam dan mengurutkan seluruh jejak perpindahan server email dari pengirim awal hingga masuk ke inbox penerima.
- 🔗 **Analisis Tautan & Link Trap Detection:**
  - Mengekstrak seluruh URL yang tertanam di dalam bodi HTML atau *plain text* email.
  - **Deteksi Anchor Mismatch:** Mengidentifikasi secara otomatis jika teks visual link (misal: `https://bank-resmi.com`) mengarahkan ke URL tujuan yang berbeda.

---

## 🚀 Cara Memulai

### Prasyarat
Pastikan Anda sudah menginstal **Python 3.8+** di komputer Anda.

### 1. Kloning Repositori
```bash
git clone [https://github.com/USERNAME-ANDA/NAMA-REPO-ANDA.git](https://github.com/USERNAME-ANDA/NAMA-REPO-ANDA.git)
cd NAMA-REPO-ANDA
