<div align="center">
  <img src="https://img.icons8.com/color/128/000000/security-checked--v1.png" alt="PhishShield Logo" width="100"/>

  # 🛡️ PhishShield AI
  
  **An Advanced, AI-Powered Cybersecurity Engine for Phishing Detection & Threat Analysis**

  [![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](#) [![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](#) [![React](https://img.shields.io/badge/react-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)](#) [![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](#) [![Google Gemini](https://img.shields.io/badge/Google%20Gemini-8E75B2?style=for-the-badge&logo=google&logoColor=white)](#) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](#)
  
  ---
</div>

PhishShield AI is an enterprise-grade cybersecurity application built to preemptively detect, analyze, and neutralize phishing attempts. By orchestrating **Google Gemini 2.5 Flash**, **VirusTotal Threat Intelligence**, **Playwright Sandboxing**, and **Computer Vision**, PhishShield acts as a comprehensive SOC (Security Operations Center) analyst automated in software.

## 📑 Table of Contents
- [✨ Core Capabilities](#-core-capabilities)
- [🏗️ System Architecture](#-system-architecture)
- [🛠️ Tech Stack](#-tech-stack)
- [🚀 Getting Started](#-getting-started)
- [⚙️ Environment Variables](#️-environment-variables)
- [🐳 Running with Docker](#-running-with-docker)
- [💻 Running Locally (Without Docker)](#-running-locally-without-docker)
- [📡 API Documentation](#-api-documentation)
- [🤝 Contributing](#-contributing)
- [📝 License](#-license)

---

## ✨ Core Capabilities

- 🧠 **AI-Powered Threat Engine**: Uses Gemini 2.5 Flash to contextually analyze emails and website payloads, understanding the nuanced differences between legitimate support requests and credential theft.
- 👁️ **Computer Vision & OCR**: Employs PyTesseract, OpenCV, and PyZbar to extract hidden text and decode malicious QR codes or barcodes from image assets.
- 🕸️ **Automated Browser Sandboxing**: Safely detonates suspicious URLs in a headless Playwright Chromium environment, capturing network requests, page contents, and visual screenshots without risking the host machine.
- 🛡️ **Global Threat Intelligence**: Integrates directly with the VirusTotal v3 API to cross-reference URLs against dozens of global security vendors.
- 💾 **Persistent Threat Logging**: Uses an SQLite database (via SQLAlchemy) to maintain a historical ledger of all intercepted threats, scores, and verdicts.
- 🎨 **Modern Interface**: A lightning-fast, responsive dashboard built on React & Vite.

---

## 🏗️ System Architecture

1. **Client / Frontend**: React application that submits emails, URLs, or images for analysis.
2. **FastAPI Gateway**: Handles incoming requests, enforces CORS, and coordinates the analysis pipeline.
3. **Primary Filters**:
   - URL Whitelist validation (e.g., `microsoft.com`, `github.com`).
   - VirusTotal lookup for known bad reputation.
4. **Deep Analysis Sandbox**:
   - Text/Email goes straight to the AI Threat Engine.
   - Images are processed via OpenCV/OCR to extract hidden payloads.
   - Unknown URLs are opened in Playwright to intercept background network traffic and scrape DOM contents.
5. **AI Evaluation**: Scraped data, OCR text, and network maps are fed to Gemini 2.5 Flash, acting as a virtual SOC Analyst.
6. **Data Persistence**: The final Threat Score, Verdict, and Analysis Details are committed to the SQLite `scan_logs` table.

---

## 🛠️ Tech Stack

### Backend
- **Framework**: Python 3, [FastAPI](https://fastapi.tiangolo.com/), Uvicorn
- **AI/ML**: `google-genai` (Gemini 2.5 Flash)
- **Computer Vision**: OpenCV (`opencv-python-headless`), PyTesseract (OCR), PyZbar (QR/Barcode)
- **Automation**: Playwright (Async Headless Chromium)
- **Database**: SQLite & SQLAlchemy (ORM)
- **Integrations**: VirusTotal v3 API

### Frontend
- **Framework**: React 19, Vite
- **Styling**: Vanilla CSS (or your chosen framework)
- **Linting**: ESLint

---

## 🚀 Getting Started

### Prerequisites
Before you begin, ensure you have the following installed:
- [Docker Desktop](https://www.docker.com/products/docker-desktop) (Recommended)
- [Node.js 20+](https://nodejs.org/) (If running locally)
- [Python 3.10+](https://www.python.org/) (If running locally)
- **Tesseract-OCR** system binaries (If running locally on Windows/Mac/Linux)

---

## ⚙️ Environment Variables

Copy the provided example environment file to configure your secrets:

```bash
cp .env.example .env
```

Open `.env` and configure the following:

| Variable | Description | Required |
|----------|-------------|----------|
| `GEMINI_API_KEY` | Your Google Gemini API Key (Needed for the AI Threat Engine) | **Yes** |
| `VT_API_KEY` | Your VirusTotal API Key (Needed for URL reputation checks) | **Yes** |

*(You can get a Gemini key from Google AI Studio, and a VT key by registering at VirusTotal.com)*

---

## 🐳 Running with Docker

The absolute easiest way to run PhishShield AI without worrying about system dependencies (like installing Tesseract or Playwright browsers) is via Docker Compose.

1. **Build and start the containers:**
   ```bash
   docker-compose up --build
   ```
2. **Access the Application:**
   - **Frontend UI**: [http://localhost:5173](http://localhost:5173)
   - **Backend API**: [http://localhost:8000](http://localhost:8000)
   - **Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 💻 Running Locally (Without Docker)

If you wish to develop locally outside of Docker, you will need two terminal windows.

### 1. Setup Backend
```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browser binaries
playwright install chromium

# Start the FastAPI server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
> **Note:** Running locally requires Tesseract-OCR and zbar installed on your host OS. (e.g., `apt-get install tesseract-ocr libzbar0` on Ubuntu or via `brew` on macOS).

### 2. Setup Frontend
```bash
cd frontend

# Install Node dependencies
npm install

# Start the Vite development server
npm run dev
```

---

## 📡 API Documentation

When the backend is running, full OpenAPI documentation is automatically available at `/docs`. Below is a quick overview of the core endpoints:

| Method | Endpoint | Description | Payload |
|--------|----------|-------------|---------|
| `POST` | `/api/analyze` | Contextually analyzes email or raw text. | JSON: `content`, `sender` |
| `POST` | `/api/scan-image` | Extracts text/QR codes from an image and analyzes it. | Form-Data: `file`, `sender` |
| `POST` | `/api/scan-url` | Sandboxes a URL, scrapes contents, and scores the threat. | JSON: `url` |
| `GET`  | `/api/history` | Retrieves historical scan logs from the database. | None |

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

<div align="center">
  <i>Defending the web, one byte at a time.</i>
</div>
