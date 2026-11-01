# CyberTrace
### Digital Forensics Timeline Analyzer

CyberTrace is a digital forensics platform developed to support structured cybersecurity investigations through evidence collection, preservation, log analysis, timeline reconstruction, and cross-source event correlation.

The platform consolidates supported system logs into a unified investigation workspace while maintaining visibility into evidence integrity, timestamp uncertainty, parsing issues, and collection coverage.

---

## Project Overview

During a cybersecurity incident, investigators often need to examine log records collected from different systems and services. Differences in timestamp formats, incomplete records, and fragmented evidence can make manual analysis difficult and time-consuming.

CyberTrace provides a centralized workflow for organizing digital evidence and reconstructing event timelines. It helps investigators review system activity, identify potentially related events, assess evidence quality, and prepare investigation reports.

| Project Information | Details |
|---|---|
| Project Domain | Cybersecurity / Digital Forensics |
| Hackathon | AIORI-3 Hackathon |
| Problem Statement | PS-013 – Incident Timeline and Evidence Collection Support |
| Team | Team Ignite |

---

## Documentation

| Document | Description |
|---|---|
| [Final Project Report (PDF)](reports/CyberTrace_Project_Report.pdf) | Complete project documentation, architecture, implementation, testing, and evaluation |
| [Hackathon Presentation (PDF)](reports/CyberTrace-Hackathon-Presentation.pdf) | Project presentation |

---

## Core Features

### Evidence Collection and Preservation

- Manual evidence upload
- Optional Linux endpoint log collection agent
- Preservation of original evidence files
- SHA-256 hash calculation and integrity verification
- Evidence metadata and audit records

### Log Analysis and Timeline Reconstruction

- Parsing of supported Linux authentication logs
- Parsing of Apache and nginx access logs
- Timestamp normalization when sufficient timezone information is available
- Unified, searchable forensic timeline
- Event filtering by time, source, hostname, username, IP address, and other supported fields
- Preservation of raw log references and parsing issues

### Evidence Quality and Coverage

- Collection coverage tracking
- Collection-gap identification
- Parsing counters and issue reporting
- Timestamp uncertainty indicators
- Evidence integrity status
- Duplicate-event reconciliation
- Evidence audit trail

### Cross-Source Correlation

- Rule-based matching of events across evidence sources
- Shared identifier analysis, including IP addresses and usernames
- Explainable correlation results
- Confidence distinctions for correlation types
- Investigator review of potential relationships

### Investigation Reporting

- PDF investigation reports
- CSV exports for supported investigation data
- Evidence and timeline summaries for further analysis

---

## System Architecture

```text
                 Evidence Sources
        Linux Authentication / Web Logs
                         |
                         v
                Evidence Collection
          Manual Upload / Linux Agent
                         |
                         v
               Evidence Preservation
              Metadata + SHA-256 Hash
                         |
                         v
               Log Parsing and
             Timestamp Normalization
                         |
                         v
                Unified Event Store
                         |
              +----------+----------+
              |                     |
              v                     v
       Timeline Analysis      Evidence Quality
              |                and Coverage
              v                     |
      Cross-Source Correlation      |
              |                     |
              +----------+----------+
                         |
                         v
             Investigation Dashboard
                         |
                         v
                PDF / CSV Reports
```

---

## Technology Stack

| Layer | Technologies |
|---|---|
| Backend API | Python, FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Database Migrations | Alembic |
| Endpoint Collection Agent | Python |
| Agent Local Queue | SQLite |
| Frontend | HTML, CSS, JavaScript |
| API Documentation | OpenAPI / FastAPI |
| Automated Testing | pytest |
| Code Quality | Ruff |
| Containerization | Docker, Docker Compose |

---

## Repository Structure

```text
Cyber_Trace/
├── agent/          # Linux endpoint collection agent
├── backend/        # API, processing services, and web application
├── docs/           # Project documentation
├── reports/        # Final report and presentation
├── samples/        # Synthetic investigation scenarios
├── scripts/        # Utility and verification scripts
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Getting Started

### Prerequisites

- Git
- Python version supported by the project requirements
- PostgreSQL
- Docker and Docker Compose (optional, for containerized deployment)

### Clone the Repository

```bash
git clone https://github.com/aiori-hackathon/A3-PS013-TC189.git
cd A3-PS013-TC189
```

### Configure the Environment

Create a local environment file from the provided template:

```bash
cp .env.example .env
```

Configure the required application and database settings in `.env`.

> Do not commit `.env` files, credentials, tokens, or other sensitive information.

### Run with Docker

```bash
docker compose up --build
```

Refer to `docker-compose.yml` and the project setup documentation for configured service ports and environment requirements.

### Run Locally

For local development:

1. Configure PostgreSQL.
2. Install backend dependencies using the requirements provided in `backend/`.
3. Configure the required environment variables.
4. Apply database migrations using Alembic.
5. Start the FastAPI application using the project’s backend instructions.

---

## Application Interfaces

| Route | Purpose |
|---|---|
| `/` | Investigation dashboard and unified timeline |
| `/workspace` | Evidence workspace |
| `/agents` | Endpoint agent and collection status |
| `/quality` | Evidence quality, integrity, coverage, and audit information |
| `/docs` | Interactive API documentation |

---

## Testing and Verification

CyberTrace includes automated backend and agent tests, synthetic investigation scenarios, and end-to-end verification.

Run the backend tests from the backend directory:

```bash
pytest
```

Run the agent tests from the agent directory:

```bash
pytest
```

The project has been tested using automated tests and synthetic datasets. Refer to the [Final Project Report](reports/CyberTrace_Project_Report.pdf) and repository verification documentation for the recorded evaluation results.

---

## Evidence and Analysis Considerations

CyberTrace is designed to support evidence-aware investigation workflows.

- SHA-256 verification checks whether stored evidence matches its recorded baseline.
- Hash verification does not independently establish evidence authenticity before collection.
- Timestamp uncertainty is retained when source metadata is incomplete.
- Collection gaps indicate limitations in available evidence and should not be interpreted as proof that no activity occurred.
- Correlation results are investigative leads and do not independently prove an attack or common actor.
- Original evidence is preserved separately from derived analysis and reports.

---

## Limitations

- Correlation rules may produce false positives and require investigator review.
- Shared identifiers such as IP addresses or hostnames may represent unrelated activity.
- Missing timestamps and collection gaps can limit event ordering and interpretation.
- The current implementation is a prototype intended for controlled investigations and academic demonstration.
- Production-grade investigator authentication, role-based access control, and deployment hardening are not fully implemented.

---

## Future Enhancements

- Investigator authentication and role-based access control
- Signed evidence manifests and tamper-evident audit storage
- Support for additional log formats and operating systems
- Improved performance for large investigations
- Expanded timeline analysis and correlation capabilities
- Enhanced deployment security, monitoring, backup, and recovery

---

## Team

**Team Ignite**

- Kishore Parasuraman
- Jabez Gabrilraj

---

## License

Refer to the repository for license information.

---

CyberTrace provides an organized approach to digital evidence collection and timeline analysis, helping investigators review system activity with greater traceability, context, and transparency.
