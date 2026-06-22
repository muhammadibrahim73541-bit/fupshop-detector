# FupShop Detector

> A browser extension and web-based tool that detects fraudulent online shops in real time by analyzing URLs, domain reputation, and web page content.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running Locally](#running-locally)
- [Docker Setup](#docker-setup)
- [Browser Extension Setup](#browser-extension-setup)
- [API Endpoints](#api-endpoints)
- [Environment Variables](#environment-variables)
- [Deployment](#deployment)
- [Authors](#authors)
- [License](#license)

---

## Overview

FupShop helps users identify scam websites before they enter personal or payment information. It checks URLs against multiple threat intelligence sources, analyzes domain age, SSL certificates, and page content for red flags commonly found in fake e-commerce sites.

The project was built as a semester project at Aalborg University for the Data Engineering and Machine Learning Operations course.

---

## Features

| Feature | Description |
|---------|-------------|
| **Real-time URL Scanning** | Submit any URL and get an instant risk assessment |
| **Multi-Source Threat Intel** | Queries VirusTotal, URLhaus, and OpenPhish APIs |
| **Domain Analysis** | WHOIS lookup for domain age, registrar, and registration details |
| **Content Scanning** | Detects typosquatting, suspicious forms, missing SSL, and scam indicators |
| **ML Scoring** | XGBoost model assigns a scam probability score (0-100%) |
| **CVR Validation** | Validates Danish CVR numbers for shop legitimacy |
| **Web Dashboard** | Gradio-based interface with scan history and detailed breakdowns |
| **SQLite Database** | Persistent storage for scan history and results |
| **Dockerized** | Full containerization for easy deployment |
| **Hugging Face Deployment** | Gradio frontend hosted on Hugging Face Spaces |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Browser Extension** | Manifest V3, JavaScript |
| **Backend API** | FastAPI, Python 3.10+ |
| **Frontend Dashboard** | Gradio |
| **ML Model** | XGBoost (scam probability scoring) |
| **Data Storage** | SQLite |
| **Threat Intelligence** | VirusTotal API, URLhaus API, OpenPhish API |
| **Containerization** | Docker |
| **Deployment** | Hugging Face Spaces |

---

## Project Structure

```
fupshop/
├── extension/                  # Browser extension (Manifest V3)
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── popup.css
│   ├── content.js
│   ├── background.js
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
├── backend/                    # FastAPI backend
│   ├── main.py                 # FastAPI application entry point
│   ├── models.py               # Pydantic schemas & data models
│   ├── database.py             # SQLite database setup & operations
│   ├── scanner.py              # URL analysis & threat intel logic
│   ├── ml_model.py             # XGBoost model loading & inference
│   ├── features.py             # Feature extraction for ML model
│   ├── cvr_validator.py        # Danish CVR number validation
│   ├── url_utils.py            # URL normalization & parsing
│   └── config.py               # Configuration & settings
│
├── frontend/                   # Gradio web interface
│   ├── app.py                  # Gradio application
│   └── components.py           # UI components
│
├── data/
│   ├── training_data/          # Dataset for model training
│   ├── models/                 # Saved XGBoost model files
│   └── fupshop.db              # SQLite database (created at runtime)
│
├── tests/                      # Unit & integration tests
│   ├── test_scanner.py
│   ├── test_cvr.py
│   └── test_features.py
│
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker image definition
├── docker-compose.yml          # Docker Compose configuration
├── .env.example                # Example environment variables
├── .gitignore
└── README.md                   # This file
```

---

## How It Works

1. **URL Input** -- User submits a URL via the browser extension or Gradio web UI.
2. **Normalization** -- The URL is cleaned and standardized for consistent analysis.
3. **Multi-Source Check** -- The system queries VirusTotal, URLhaus, and OpenPhish for known malicious domains.
4. **Domain Analysis** -- WHOIS lookup checks domain age, registrar, and registration details.
5. **Content Scan** -- Page content is analyzed for scam indicators:
   - Typosquatting detection
   - Suspicious form fields (credit card, password harvesting)
   - Missing or invalid SSL certificates
   - Hidden redirects
   - Fake trust badges
6. **ML Scoring** -- XGBoost model processes extracted features and assigns a scam probability score (0-100%).
7. **Result Display** -- User sees a clear risk verdict with a detailed breakdown of all checks performed.

---

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Docker & Docker Compose (optional, for containerized deployment)
- Google Chrome (for browser extension)
- API keys for:
  - [VirusTotal](https://www.virustotal.com/)
  - [URLhaus](https://urlhaus-api.abuse.ch/)
  - [OpenPhish](https://openphish.com/)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/muhammadibrahim73541-bit/fupshop.git
cd fupshop
```

### 2. Set Up Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLHAUS_API_KEY=your_urlhaus_api_key
OPENPHISH_API_KEY=your_openphish_api_key
DATABASE_PATH=data/fupshop.db
MODEL_PATH=data/models/xgboost_model.pkl
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## Running Locally

### Backend (FastAPI)

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at: `http://localhost:8000`

Interactive API docs (Swagger UI): `http://localhost:8000/docs`

### Frontend (Gradio)

```bash
cd frontend
python app.py
```

The Gradio interface will be available at: `http://localhost:7860`

### Running Both Together

You can run both backend and frontend simultaneously in separate terminal windows, or use Docker Compose (recommended).

---

## Docker Setup

### Build the Docker Image

```bash
docker build -t fupshop .
```

### Run the Container

```bash
docker run -d   --name fupshop   -p 8000:8000   -p 7860:7860   -e VIRUSTOTAL_API_KEY=your_key   -e URLHAUS_API_KEY=your_key   -e OPENPHISH_API_KEY=your_key   -v $(pwd)/data:/app/data   fupshop
```

### Using Docker Compose (Recommended)

```bash
docker-compose up -d
```

This will start both the FastAPI backend and Gradio frontend with all environment variables loaded from `.env`.

### Stop the Container

```bash
docker-compose down
```

### View Logs

```bash
docker logs -f fupshop
```

### Rebuild After Changes

```bash
docker-compose up -d --build
```

---

## Browser Extension Setup

1. Open Google Chrome and navigate to: `chrome://extensions/`
2. Enable **Developer Mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `extension/` folder from this repository
5. The FupShop extension icon will appear in your Chrome toolbar
6. Click the icon on any webpage to scan the current URL

### Extension Features

- **Popup Interface** -- Click the extension icon to scan the current tab's URL
- **Real-time Badge** -- Extension icon changes color based on risk level
- **Auto-scan** -- Optional: automatically scan URLs when visiting new pages
- **Quick Report** -- Submit suspicious sites to improve the detection model

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Submit a URL for full analysis |
| `GET` | `/scan/{scan_id}` | Retrieve scan results by ID |
| `GET` | `/history` | Get scan history (paginated) |
| `POST` | `/validate-cvr` | Validate a Danish CVR number |
| `GET` | `/health` | Health check endpoint |
| `GET` | `/docs` | Interactive API documentation (Swagger UI) |

### Example: Scan a URL

```bash
curl -X POST "http://localhost:8000/scan"   -H "Content-Type: application/json"   -d '{"url": "https://example-shop.com"}'
```

### Example Response

```json
{
  "scan_id": "abc123",
  "url": "https://example-shop.com",
  "risk_score": 87,
  "risk_level": "HIGH",
  "verdict": "LIKELY SCAM",
  "checks": {
    "virustotal": "malicious",
    "domain_age": "3 days",
    "ssl_valid": false,
    "cvr_match": false,
    "typosquatting": true,
    "suspicious_forms": true
  },
  "timestamp": "2026-06-22T08:15:00Z"
}
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VIRUSTOTAL_API_KEY` | Yes | API key for VirusTotal lookups |
| `URLHAUS_API_KEY` | Yes | API key for URLhaus threat feed |
| `OPENPHISH_API_KEY` | Yes | API key for OpenPhish database |
| `DATABASE_PATH` | No | SQLite database file path (default: `data/fupshop.db`) |
| `MODEL_PATH` | No | Path to XGBoost model file (default: `data/models/xgboost_model.pkl`) |
| `LOG_LEVEL` | No | Logging level: DEBUG, INFO, WARNING, ERROR (default: INFO) |
| `MAX_SCAN_AGE_DAYS` | No | Cache scan results for N days (default: 7) |

---

## Deployment

### Hugging Face Spaces

The Gradio frontend is deployed on **Hugging Face Spaces** for public access:

```
https://huggingface.co/spaces/muhammadibrahim73541/fupshop
```

To deploy updates:

```bash
# Ensure you have the Hugging Face CLI installed
pip install huggingface-hub

# Login
huggingface-cli login

# Push to Space
git push huggingface main
```

### Docker Hub (Optional)

Build and push to Docker Hub:

```bash
docker build -t yourusername/fupshop:latest .
docker push yourusername/fupshop:latest
```

---

## Authors

- **Muhammad Ibrahim** -- [@muhammadibrahim73541-bit](https://github.com/muhammadibrahim73541-bit)
- **Asalun Hye Arnob** -- Teammate & Contributor

---

## License

This project is licensed for academic purposes. See LICENSE file for details.

---
