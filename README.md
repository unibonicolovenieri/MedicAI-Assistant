# MedicAI - Secure Medical Assistant

A privacy-first conversational AI assistant for medical practice management. The system implements multi-layer security architecture to protect patient data while providing intelligent appointment booking and medical information services.

## Architecture

### Core Components

**secure_main.py**
Main application with three-layer security architecture:
- AI Firewall: ML-based threat detection with pattern matching
- Privacy Checker: Deterministic GDPR-compliant access control
- Audit Logger: Complete security event logging (JSONL format)

**database/letta_client.py**
HTTP API client for Letta AI integration:
- Agent-per-patient architecture for isolated memory contexts
- Conversational memory persistence
- Appointment storage and semantic search
- Uses letta/letta-free model (no API costs)

**tools/medical_tools.py**
MemoryDB class providing fallback in-memory database:
- Patient authentication with timing-safe PIN comparison
- Appointment management (create, list, filter)
- Session management
- Acts as primary data store when Letta is unavailable

**tools/ollama_client.py**
Integration with Ollama (llama3.2:latest) for natural language processing:
- Generic query responses with medical context
- Runs locally on localhost:11434
- Zero external data transmission
- Graceful degradation if unavailable

**security/ai_firewall.py**
First security layer with 40+ threat patterns:
- SQL injection detection
- Prompt injection blocking
- Unicode normalization
- Rate limiting (10 req/min per session)

**security/audit_logger.py**
GDPR-compliant logging system with four streams:
- security_incidents.jsonl
- access_audit.jsonl
- authentication.jsonl
- pii_events.jsonl

### Letta Integration Files

The `letta/` directory contains modules for Letta server integration and access control:
clone original Letta git, paste the following files in the right directories.

**letta/app.py**
Modified Letta server application with medical access middleware integration. Handles FastAPI routing, error handling, and lifecycle management for the Letta agent server.

**letta/medical_access_control.py**
Schema definitions for medical access control:
- MedicalRole enum: PATIENT, DOCTOR, SECRETARY, GUARD
- DataSensitivityLevel: PUBLIC, RESTRICTED, CONFIDENTIAL, CRITICAL
- MedicalAccessPolicy: Role-based access policies with audit logging
- MedicalContextFilter: Query filtering based on user role and patient ownership

**letta/medical_access_manager.py**
Service for GDPR-compliant message filtering:
- filter_messages_by_medical_access(): Filters agent messages based on user role
- Role-based data access enforcement
- Audit trail for all data access attempts
- Patient ownership verification

**letta/medical_access.py**
FastAPI middleware for request-level access control:
- Extracts X-Medical-Role and X-Patient-ID headers
- Validates medical roles before processing requests
- Applies filtering to responses containing sensitive data
- Integrates with MedicalAccessManager for policy enforcement

These files enable role-based access control at the Letta server level, ensuring that even if the main application layer is bypassed, medical data remains protected according to GDPR requirements.

## Security Features

- 100% local execution (no external API calls)
- Multi-layer security validation
- Timing-safe authentication
- Rate limiting and abuse prevention
- Complete audit trail
- Privacy-by-design architecture

## Technology Stack

- Python 3.12
- Letta AI v0.6.5+ (HTTP API, localhost:8283)
- Ollama llama3.2:latest (localhost:11434)
- Docker (for Letta postgres and server)
- FastAPI (Letta server)
- SQLAlchemy (Letta ORM)

## Usage

```bash
# Start services
docker start letta-postgres letta
ollama serve  # in separate terminal

# Run interactive mode
python3 secure_main.py

# Login credentials
# PAZ001 - PIN: 123456 (Mario Rossi)
# PAZ002 - PIN: 654321 (Laura Bianchi)
```

## Testing

```bash
# Run security tests
python3 secure_main.py --test

# Basic penetration tests (5 tests)
python3 tests/penetration_test.py

# Advanced penetration tests (5 tests)
python3 tests/advanced_penetration_test.py
```

## Query Examples

- "Qual e il mio nome?"
- "I miei appuntamenti"
- "Prenota appuntamento per domani alle 14:30 per controllo"
- "Come posso migliorare la mia salute?" (uses Ollama)

## Logs

All security events are logged in `logs/` directory:
- security_incidents.jsonl: Blocked attacks and threats
- access_audit.jsonl: All data access operations
- authentication.jsonl: Login attempts
- pii_events.jsonl: PII access tracking
