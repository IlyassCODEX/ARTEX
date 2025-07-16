# ARTEX - Automated Reconnaissance & Threat Exposure Analyzer

![Security](https://img.shields.io/badge/Security-Pentesting-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![Flask](https://img.shields.io/badge/Flask-2.3.2-lightgrey)

ARTEX is an advanced web application security analysis platform that automates reconnaissance, vulnerability scanning, vulnerability scanning, threat assessment and AI-powered security recommendations  for modern web applications and infrastructure.

## Key Features

- **Comprehensive Scanning**:
  - Subdomain enumeration
  - Port scanning with risk assessment
  - Technology stack fingerprinting
  - Authentication surface detection

- **Intelligent Analysis**:
  - AI-powered security recommendations (Groq/Llama3 integration)
  - Dual-perspective reports (Owner vs Hunter views)
  - Automated risk scoring

- **Enterprise Ready**:
  - Parallel scanning engine
  - PDF/JSON report generation
  - REST API for integration

## Installation

### Prerequisites
- Python 3.8+
- Nmap (system installation)
- Redis (for job queueing - optional)

```bash
# Ubuntu/Debian
sudo apt-get install nmap wkhtmltopdf

# macOS
brew install nmap wkhtmltopdf
```

Setup
```bash

git clone https://github.com/yourrepo/artex.git
cd artex

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows

pip install -r requirements.txt

```
Configuration

U need to add your GROQ api key in the AI_analyst.py script , here

```bash

# AI_analyst.py
import requests
import json
from typing import Dict, List, Optional
import logging
from datetime import datetime
import time

class AIAnalyst:
    def __init__(self, groq_api_key: str = None):
        """
        Initialize the AI analyst with Groq API integration
        
        Args:
            groq_api_key: Optional Groq API key (if not provided, will use rule-based analysis only)
        """
        self.groq_api_key = "GROQ_API_KEY"
        self.logger = logging.getLogger(__name__)
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        ......
        
```

Usage
Web Interface
```bash

python app.py

Access the interface at: http://localhost:5000
API Endpoints

    POST /start_scan - Initiate new scan

    GET /scan_status/<scan_id> - Check scan progress

    GET /results/<scan_id> - View results

    GET /export/<scan_id> - Export reports (PDF/JSON)
```

Scan Types
  Scan Type	Description	Intensity Levels
  Full Audit	Complete security assessment	Light/Normal/Aggressive
  Web Focus	Application-layer only	Normal
  Infrastructure	Network and server assessment	Aggressive
  Quick Scan	Surface-level vulnerabilities	Light
  Sample Report Output

Security Notice

This tool is for authorized security assessments only. Unauthorized use against systems you don't own or have permission to test is illegal.
