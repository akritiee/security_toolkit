# 🛡️ Security Hub — Cybersecurity Toolkit

A full-stack cybersecurity web application built with **Flask (Python)** + **HTML/CSS/JavaScript**.  
Designed as a college final-year project demonstrating real-world security tools in a single dashboard.

---

## 🚀 Features

| Module | Description |
|---|---|
| 🔒 **Security Audit** | Scans your system for open ports, antivirus status, password strength |
| 🌐 **Threat Intelligence** | Checks IPs and domains against VirusTotal & AbuseIPDB |
| 📡 **Wi-Fi Auditor** | Lists nearby Wi-Fi networks and flags open/unsecured ones |
| 🖼️ **Image Scanner** | Extracts EXIF/GPS metadata and perceptual hashes from images |
| 🗺️ **Map Navigation** | Plots image match locations on an interactive Leaflet.js map |
| 🔐 **Auth** | Google OAuth via Firebase + Guest mode |

---

## 🏗️ Project Structure

```
SecurityHub/
├── app.py                  # Flask backend — all API routes
├── requirements.txt        # Python dependencies
├── .env.example            # Template for your secret keys (copy → .env)
├── .gitignore              # Keeps secrets & uploads off GitHub
├── uploads/                # Uploaded images (gitignored, folder kept)
└── templates/
    ├── first.html          # Main dashboard / login portal
    ├── threat.html         # Threat Intelligence (IP/Domain checker)
    ├── wifi.html           # Wi-Fi network scanner
    ├── system.html         # System Security Audit
    ├── Image.html          # Image OSINT scanner
    └── map.html            # Geo-location map viewer
```

---

## ⚙️ Setup & Run

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/SecurityHub.git
cd SecurityHub
```

### 2. Create a Virtual Environment
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Your API Keys

Copy the example env file and fill in your real keys:
```bash
cp .env.example .env
```

Then edit `.env`:
```
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key
FIREBASE_KEY_PATH=firebase-adminsdk.json
```

> 🔑 Get free API keys:
> - VirusTotal: https://www.virustotal.com/gui/my-apikey
> - AbuseIPDB: https://www.abuseipdb.com/account/api

### 5. Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create/open your project → **Project Settings → Service Accounts**
3. Click **Generate new private key** → download the JSON file
4. Rename it to `firebase-adminsdk.json` and place it in the project root
5. ⚠️ This file is in `.gitignore` — **never push it to GitHub**

### 6. Run the App
```bash
python app.py
```

Open your browser: **http://127.0.0.1:5000**

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/intel/check` | Check an IP or domain for threats |
| `POST` | `/api/audit` | Run a system security audit |
| `GET` | `/api/audit/summary` | Quick audit score |
| `GET` | `/api/wifi/scan` | Scan Wi-Fi networks |
| `POST` | `/api/upload-image` | Analyze image metadata & GPS |
| `POST` | `/api/analyze-bruteforce` | ML-based brute force detection |
| `POST` | `/save-intel` | Save a query result to Firebase |

---

## 🛡️ Security Notes

- **Never commit** your `.env` or Firebase JSON key to GitHub
- All secrets are loaded from environment variables via `python-dotenv`
- The `.gitignore` is pre-configured to exclude all sensitive files

---

## 🧰 Tech Stack

**Backend:** Python 3 · Flask · Firebase Admin SDK · SQLite · psutil · scikit-learn · Pillow · ImageHash  
**Frontend:** HTML5 · CSS3 · Vanilla JavaScript · Leaflet.js · Chart.js  
**Auth:** Firebase Google OAuth  
**APIs:** VirusTotal · AbuseIPDB · OpenStreetMap

---

## 📸 Screenshots

> Add screenshots of your dashboard here after running the project.

---

## 📄 License

This project is for educational purposes. MIT License.
