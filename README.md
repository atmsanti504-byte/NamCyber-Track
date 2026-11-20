# 🇳🇦 NamCyber Track

### A centralised cybersecurity incident reporting and tracking platform for Namibia.

NamCyber Track is a web-based platform designed to help individuals and organisations report, document and monitor cybersecurity incidents, including online scams, cyberattacks and digital fraud.

The platform provides a centralised reporting interface and an administrative dashboard to support incident management, threat visibility and the identification of recurring indicators across reported incidents.

**Project status:** Prototype  
**Technology:** Python · Flask · SQLite · HTML · CSS · JavaScript

---

## 🎯 The Problem

Cybersecurity incidents, online scams and digital fraud can be difficult to track when reports are fragmented across different channels and organisations.

This limits visibility into recurring threats, makes incident follow-up difficult and reduces opportunities to identify connections between reported cases.

NamCyber Track aims to address this challenge through a structured and accessible incident reporting and tracking platform.

## 💡 Our Solution

NamCyber Track provides two primary interfaces:

- **Public Reporting Portal:** Allows individuals and organisations to submit structured reports about cybersecurity incidents.
- **Administrative Dashboard:** Enables authorised responders to review, manage, investigate and analyse submitted reports.

## ✨ Key Features

### Public Incident Reporting
- Structured cybersecurity incident submission.
- Incident category, attack vector and severity classification.
- Location and impact information.
- Submission of indicators such as suspicious URLs, IP addresses, email addresses and file hashes.
- Supporting evidence and anonymous reporting options.
- Unique incident reference numbers.

### Administrative Dashboard
- Overview of reported incidents and statistics.
- Search and filtering of incident reports.
- Incident severity and status management.
- Case assignment and investigation notes.
- Identification of related reports through shared indicators.
- CSV report export.
- Critical incident notifications through configurable webhooks.

### Security and Data Management
- Protected administrative access.
- Input validation and submission rate limiting.
- SQLite database for prototype data storage.
- Separation between public reporting and administrative functions.

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Web framework | Flask |
| Notifications | Configurable webhook integration |

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or later recommended.
- Git.
- Windows, Linux or macOS.

### 1. Clone the repository

```bash
git clone https://github.com/atmsanti504-byte/NamCyber-Track.git
cd NamCyber-Track
```

### 2. Navigate to the application directory

If using the repository's current folder structure:

```bash
cd namcyber-track
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

On Linux/macOS:

```bash
source venv/bin/activate
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure environment variables

For Windows PowerShell:

```powershell
$env:SECRET_KEY = "replace-with-a-strong-random-secret"
$env:ADMIN_PASSWORD = "choose-a-strong-admin-password"
```

For Linux/macOS:

```bash
export SECRET_KEY="replace-with-a-strong-random-secret"
export ADMIN_PASSWORD="choose-a-strong-admin-password"
```

Use unique secrets and do not commit them to GitHub.

### 6. Start the application

```bash
python server.py
```

### 7. Access the application

| Interface | Address |
|---|---|
| Public reporting portal | http://127.0.0.1:5000 |
| Administrative dashboard | http://127.0.0.1:5000/admin |

## 🗺️ Future Development

Potential areas of further development include:

- Cloud deployment and improved scalability.
- Integration with relevant cybersecurity stakeholders.
- Expanded threat intelligence enrichment.
- Secure information-sharing capabilities.
- Additional reporting channels.
- Improved incident analytics and visualisation.

## ⚠️ Prototype Disclaimer

NamCyber Track is currently a demonstration prototype intended to showcase its core reporting and incident management capabilities.

It is not yet a publicly deployed national incident reporting service. The current version runs locally, and production deployment would require additional security testing, infrastructure, data protection measures and operational partnerships.

Any sample incidents or statistics used during demonstrations are fictional.

## 👥 Project Team

**David Sakaria** – Original Concept Creator / Technical Direction

**Asante-Sana Maruwasa** – Project Lead / Project Coordination

## 📄 Licence

This project is distributed under the MIT Licence. See [LICENSE](LICENSE) for details.

---

*Building towards a more connected and cyber-resilient Namibia.* 🇳🇦
