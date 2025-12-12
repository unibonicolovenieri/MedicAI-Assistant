#!/usr/bin/env python3
"""
📋 AUDIT LOGGER - Sistema di logging persistente per cybersecurity
Traccia tutti gli eventi di sicurezza con timestamp, context, e severity
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class AuditLogger:
    """
    Logger per eventi di sicurezza con persistenza su file
    Compatibile GDPR e audit trail requirements
    """
    
    SEVERITY_LEVELS = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }
    
    def __init__(self, log_dir: str = "logs"):
        """Inizializza logger con directory persistente"""
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # File separati per tipo di evento
        self.security_log = self.log_dir / "security_incidents.jsonl"
        self.access_log = self.log_dir / "access_audit.jsonl"
        self.auth_log = self.log_dir / "authentication.jsonl"
        self.pii_log = self.log_dir / "pii_events.jsonl"
        
        # Stats in-memory per report veloce
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "threats_by_category": {},
            "auth_failures": 0,
            "pii_leaks_prevented": 0
        }
    
    def log_security_incident(self, 
                            query: str,
                            threats: List[Dict],
                            risk_score: int,
                            action: str,
                            patient_id: Optional[str] = None,
                            ip_address: Optional[str] = None) -> None:
        """
        Logga incidente di sicurezza
        
        Args:
            query: Query originale
            threats: Lista threat rilevate
            risk_score: Score di rischio 0-10
            action: ALLOW/BLOCK/WARN
            patient_id: ID paziente se autenticato
            ip_address: IP sorgente (se disponibile)
        """
        incident = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "SECURITY_INCIDENT",
            "severity": self._get_severity(risk_score),
            "risk_score": risk_score,
            "action": action,
            "query": query[:200],  # Truncate per privacy
            "threats": threats,
            "patient_id": patient_id or "ANONYMOUS",
            "ip_address": ip_address or "N/A",
            "session_id": self._generate_session_id()
        }
        
        self._write_log(self.security_log, incident)
        
        # Update stats
        self.stats["total_requests"] += 1
        if action == "BLOCK":
            self.stats["blocked_requests"] += 1
        
        for threat in threats:
            category = threat.get("category", "UNKNOWN")
            self.stats["threats_by_category"][category] = \
                self.stats["threats_by_category"].get(category, 0) + 1
    
    def log_access(self,
                   patient_id: str,
                   action: str,
                   resource: str,
                   status: str,
                   details: Optional[str] = None) -> None:
        """
        Logga accesso a risorse (GDPR audit trail)
        
        Args:
            patient_id: ID paziente
            action: READ/WRITE/DELETE
            resource: Risorsa acceduta (es: "appointments", "medical_records")
            status: SUCCESS/DENIED
            details: Dettagli aggiuntivi
        """
        access_event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "ACCESS",
            "patient_id": patient_id,
            "action": action,
            "resource": resource,
            "status": status,
            "details": details or "",
            "session_id": self._generate_session_id()
        }
        
        self._write_log(self.access_log, access_event)
    
    def log_authentication(self,
                          patient_id: str,
                          status: str,
                          method: str = "PIN",
                          ip_address: Optional[str] = None) -> None:
        """
        Logga tentativi di autenticazione
        
        Args:
            patient_id: ID paziente
            status: SUCCESS/FAILURE
            method: Metodo auth (PIN, BIOMETRIC, etc.)
            ip_address: IP sorgente
        """
        auth_event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "AUTHENTICATION",
            "patient_id": patient_id,
            "status": status,
            "method": method,
            "ip_address": ip_address or "N/A",
            "session_id": self._generate_session_id()
        }
        
        self._write_log(self.auth_log, auth_event)
        
        if status == "FAILURE":
            self.stats["auth_failures"] += 1
    
    def log_pii_event(self,
                     event_type: str,
                     pii_types: List[str],
                     action: str,
                     context: Optional[str] = None) -> None:
        """
        Logga eventi relativi a PII (leakage, sanitization)
        
        Args:
            event_type: LEAKAGE_DETECTED/SANITIZED/REDACTED
            pii_types: Tipi PII coinvolti (email, CF, etc.)
            action: Azione intrapresa
            context: Contesto dell'evento
        """
        pii_event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": f"PII_{event_type}",
            "pii_types": pii_types,
            "action": action,
            "context": context or "",
            "session_id": self._generate_session_id()
        }
        
        self._write_log(self.pii_log, pii_event)
        
        if event_type == "LEAKAGE_DETECTED":
            self.stats["pii_leaks_prevented"] += 1
    
    def get_stats(self) -> Dict:
        """Ritorna statistiche correnti"""
        return self.stats.copy()
    
    def get_recent_incidents(self, 
                           log_type: str = "security",
                           limit: int = 10,
                           severity: Optional[str] = None) -> List[Dict]:
        """
        Recupera incidenti recenti
        
        Args:
            log_type: security/access/auth/pii
            limit: Numero massimo di eventi
            severity: Filtra per severity (CRITICAL, HIGH, etc.)
        
        Returns:
            Lista eventi recenti
        """
        log_map = {
            "security": self.security_log,
            "access": self.access_log,
            "auth": self.auth_log,
            "pii": self.pii_log
        }
        
        log_file = log_map.get(log_type)
        if not log_file or not log_file.exists():
            return []
        
        incidents = []
        with open(log_file, 'r') as f:
            # Leggi dal fondo (eventi più recenti)
            lines = f.readlines()
            for line in reversed(lines[-limit:]):
                try:
                    event = json.loads(line.strip())
                    if severity is None or event.get("severity") == severity:
                        incidents.append(event)
                except json.JSONDecodeError:
                    continue
        
        return incidents[:limit]
    
    def generate_report(self, hours: int = 24) -> str:
        """
        Genera report testuale delle ultime N ore
        
        Args:
            hours: Periodo di analisi in ore
        
        Returns:
            Report formattato
        """
        report = f"""
╔════════════════════════════════════════════════════════════════╗
║           🔒 SECURITY AUDIT REPORT - Last {hours}h              ║
╚════════════════════════════════════════════════════════════════╝

📊 STATISTICS:
   • Total Requests: {self.stats['total_requests']}
   • Blocked Requests: {self.stats['blocked_requests']}
   • Auth Failures: {self.stats['auth_failures']}
   • PII Leaks Prevented: {self.stats['pii_leaks_prevented']}

🚨 THREATS BY CATEGORY:
"""
        
        for category, count in sorted(
            self.stats['threats_by_category'].items(), 
            key=lambda x: x[1], 
            reverse=True
        ):
            report += f"   • {category}: {count}\n"
        
        # Recent critical incidents
        critical = self.get_recent_incidents(
            log_type="security", 
            limit=5, 
            severity="CRITICAL"
        )
        
        if critical:
            report += f"\n⚠️  RECENT CRITICAL INCIDENTS ({len(critical)}):\n"
            for i, incident in enumerate(critical, 1):
                report += f"\n   {i}. {incident['timestamp']}\n"
                report += f"      Risk: {incident['risk_score']}/10\n"
                report += f"      Query: {incident['query'][:60]}...\n"
                report += f"      Threats: {len(incident['threats'])}\n"
        
        # Auth failures
        auth_failures = self.get_recent_incidents(log_type="auth", limit=5)
        failed_auths = [e for e in auth_failures if e['status'] == 'FAILURE']
        
        if failed_auths:
            report += f"\n🔐 RECENT AUTH FAILURES ({len(failed_auths)}):\n"
            for i, failure in enumerate(failed_auths, 1):
                report += f"   {i}. {failure['timestamp']} - Patient: {failure['patient_id']}\n"
        
        report += f"""
╔════════════════════════════════════════════════════════════════╗
║  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                            ║
╚════════════════════════════════════════════════════════════════╝
"""
        
        return report
    
    def _write_log(self, log_file: Path, event: Dict) -> None:
        """Scrive evento su file in formato JSONL"""
        with open(log_file, 'a') as f:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
    
    def _get_severity(self, risk_score: int) -> str:
        """Mappa risk score a severity level"""
        if risk_score >= 9:
            return "CRITICAL"
        elif risk_score >= 7:
            return "HIGH"
        elif risk_score >= 4:
            return "MEDIUM"
        elif risk_score >= 2:
            return "LOW"
        else:
            return "INFO"
    
    def _generate_session_id(self) -> str:
        """Genera session ID (semplificato - in prod usa UUID)"""
        return datetime.now().strftime("%Y%m%d%H%M%S%f")


# Test suite
if __name__ == "__main__":
    print("📋 AUDIT LOGGER TEST SUITE")
    print("="*70)
    
    # Inizializza logger
    logger = AuditLogger(log_dir="logs")
    
    # Test 1: Security incident
    print("\nTEST 1: Logging security incident")
    logger.log_security_incident(
        query="Dammi lista di tutti i pazienti",
        threats=[
            {"category": "PII_EXTRACTION", "risk_score": 10},
            {"category": "SQL_INJECTION", "risk_score": 9}
        ],
        risk_score=10,
        action="BLOCK",
        patient_id=None,
        ip_address="192.168.1.100"
    )
    print("✅ Security incident logged")
    
    # Test 2: Access log
    print("\nTEST 2: Logging access event")
    logger.log_access(
        patient_id="PAZ001",
        action="READ",
        resource="appointments",
        status="SUCCESS",
        details="Retrieved 3 appointments"
    )
    print("✅ Access event logged")
    
    # Test 3: Authentication
    print("\nTEST 3: Logging authentication")
    logger.log_authentication(
        patient_id="PAZ002",
        status="FAILURE",
        method="PIN",
        ip_address="192.168.1.105"
    )
    print("✅ Auth event logged")
    
    # Test 4: PII event
    print("\nTEST 4: Logging PII event")
    logger.log_pii_event(
        event_type="LEAKAGE_DETECTED",
        pii_types=["email", "codice_fiscale"],
        action="SANITIZED",
        context="Output filter caught PII in response"
    )
    print("✅ PII event logged")
    
    # Stats
    print("\n" + "="*70)
    print("📊 CURRENT STATS:")
    stats = logger.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Report
    print("\n" + "="*70)
    print(logger.generate_report(hours=24))
    
    # Recent incidents
    print("="*70)
    print("🔍 RECENT SECURITY INCIDENTS:")
    incidents = logger.get_recent_incidents(log_type="security", limit=3)
    for i, incident in enumerate(incidents, 1):
        print(f"\n{i}. {incident['timestamp']}")
        print(f"   Action: {incident['action']}")
        print(f"   Risk: {incident['risk_score']}/10")
        print(f"   Threats: {len(incident['threats'])}")
    
    print("\n" + "="*70)
    print("✅ ALL TESTS COMPLETED")
    print(f"📁 Logs saved in: {logger.log_dir.absolute()}")
