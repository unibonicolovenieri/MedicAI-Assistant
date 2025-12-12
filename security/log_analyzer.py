#!/usr/bin/env python3
"""
📊 LOG ANALYZER - Analisi e visualizzazione log audit
Strumento per amministratori cybersecurity
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
from typing import List, Dict


class LogAnalyzer:
    """Analizzatore log per security audit"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        if not self.log_dir.exists():
            print(f"❌ Directory {log_dir} non trovata")
            return
    
    def load_log(self, log_type: str) -> List[Dict]:
        """Carica log da file JSONL"""
        log_files = {
            "security": "security_incidents.jsonl",
            "access": "access_audit.jsonl",
            "auth": "authentication.jsonl",
            "pii": "pii_events.jsonl"
        }
        
        log_file = self.log_dir / log_files.get(log_type, "")
        if not log_file.exists():
            return []
        
        events = []
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    events.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        
        return events
    
    def analyze_threats(self, hours: int = 24) -> Dict:
        """Analizza minacce rilevate"""
        incidents = self.load_log("security")
        cutoff = datetime.now() - timedelta(hours=hours)
        
        recent = [
            i for i in incidents 
            if datetime.fromisoformat(i['timestamp']) > cutoff
        ]
        
        if not recent:
            return {
                "total": 0,
                "by_severity": {},
                "by_category": {},
                "blocked": 0,
                "top_queries": []
            }
        
        severities = Counter(i['severity'] for i in recent)
        categories = Counter()
        for incident in recent:
            for threat in incident.get('threats', []):
                categories[threat.get('category', 'UNKNOWN')] += 1
        
        blocked = sum(1 for i in recent if i['action'] == 'BLOCK')
        
        # Top query pericolose
        queries = [(i['query'][:60], i['risk_score']) for i in recent]
        top_queries = sorted(queries, key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total": len(recent),
            "by_severity": dict(severities),
            "by_category": dict(categories),
            "blocked": blocked,
            "top_queries": top_queries
        }
    
    def analyze_authentication(self, hours: int = 24) -> Dict:
        """Analizza tentativi di autenticazione"""
        auth_events = self.load_log("auth")
        cutoff = datetime.now() - timedelta(hours=hours)
        
        recent = [
            e for e in auth_events 
            if datetime.fromisoformat(e['timestamp']) > cutoff
        ]
        
        if not recent:
            return {"total": 0, "success": 0, "failure": 0, "failed_patients": []}
        
        success = sum(1 for e in recent if e['status'] == 'SUCCESS')
        failure = sum(1 for e in recent if e['status'] == 'FAILURE')
        
        # Pazienti con tentativi falliti
        failed = [e['patient_id'] for e in recent if e['status'] == 'FAILURE']
        failed_counts = Counter(failed)
        
        return {
            "total": len(recent),
            "success": success,
            "failure": failure,
            "success_rate": f"{success/len(recent)*100:.1f}%" if recent else "N/A",
            "failed_patients": failed_counts.most_common(5)
        }
    
    def analyze_access(self, hours: int = 24) -> Dict:
        """Analizza accessi a risorse"""
        access_events = self.load_log("access")
        cutoff = datetime.now() - timedelta(hours=hours)
        
        recent = [
            e for e in access_events 
            if datetime.fromisoformat(e['timestamp']) > cutoff
        ]
        
        if not recent:
            return {"total": 0, "by_resource": {}, "by_patient": {}}
        
        resources = Counter(e['resource'] for e in recent)
        patients = Counter(e['patient_id'] for e in recent)
        
        return {
            "total": len(recent),
            "by_resource": dict(resources),
            "by_patient": dict(patients),
            "most_active": patients.most_common(5)
        }
    
    def analyze_pii(self, hours: int = 24) -> Dict:
        """Analizza eventi PII"""
        pii_events = self.load_log("pii")
        cutoff = datetime.now() - timedelta(hours=hours)
        
        recent = [
            e for e in pii_events 
            if datetime.fromisoformat(e['timestamp']) > cutoff
        ]
        
        if not recent:
            return {"total": 0, "leaks_prevented": 0, "pii_types": {}}
        
        leaks = sum(1 for e in recent if "LEAKAGE" in e['event_type'])
        
        pii_types = Counter()
        for event in recent:
            for pii_type in event.get('pii_types', []):
                pii_types[pii_type] += 1
        
        return {
            "total": len(recent),
            "leaks_prevented": leaks,
            "pii_types": dict(pii_types)
        }
    
    def generate_comprehensive_report(self, hours: int = 24) -> str:
        """Genera report completo"""
        threats = self.analyze_threats(hours)
        auth = self.analyze_authentication(hours)
        access = self.analyze_access(hours)
        pii = self.analyze_pii(hours)
        
        report = f"""
╔════════════════════════════════════════════════════════════════════════╗
║                   🔒 COMPREHENSIVE SECURITY REPORT                    ║
║                        Last {hours} hours                                   ║
╚════════════════════════════════════════════════════════════════════════╝

📊 EXECUTIVE SUMMARY
{'='*76}
• Security Incidents: {threats['total']} ({threats['blocked']} blocked)
• Authentication Attempts: {auth['total']} ({auth.get('success_rate', 'N/A')} success rate)
• Resource Accesses: {access['total']}
• PII Leaks Prevented: {pii['leaks_prevented']}

🚨 THREAT ANALYSIS
{'='*76}
"""
        
        if threats['total'] > 0:
            report += "\nBy Severity:\n"
            for severity, count in sorted(threats['by_severity'].items(), 
                                         key=lambda x: ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x[0]), 
                                         reverse=True):
                bar = '█' * min(count, 30)
                report += f"   {severity:10} {bar} {count}\n"
            
            report += "\nBy Category:\n"
            for category, count in sorted(threats['by_category'].items(), 
                                         key=lambda x: x[1], 
                                         reverse=True):
                report += f"   • {category}: {count}\n"
            
            if threats['top_queries']:
                report += "\nMost Dangerous Queries:\n"
                for i, (query, risk) in enumerate(threats['top_queries'], 1):
                    report += f"   {i}. (Risk {risk}/10) {query}...\n"
        else:
            report += "   ✅ No threats detected\n"
        
        report += f"""
🔐 AUTHENTICATION ANALYSIS
{'='*76}
"""
        
        if auth['total'] > 0:
            report += f"""
• Total Attempts: {auth['total']}
• Successful: {auth['success']} ✅
• Failed: {auth['failure']} ❌
• Success Rate: {auth['success_rate']}
"""
            
            if auth['failed_patients']:
                report += "\nPatients with Failed Attempts:\n"
                for patient_id, count in auth['failed_patients']:
                    report += f"   • {patient_id}: {count} failures\n"
        else:
            report += "   No authentication events\n"
        
        report += f"""
📂 ACCESS AUDIT
{'='*76}
"""
        
        if access['total'] > 0:
            report += f"• Total Accesses: {access['total']}\n\n"
            
            if access['by_resource']:
                report += "By Resource:\n"
                for resource, count in sorted(access['by_resource'].items(), 
                                             key=lambda x: x[1], 
                                             reverse=True):
                    report += f"   • {resource}: {count}\n"
            
            if access['most_active']:
                report += "\nMost Active Patients:\n"
                for patient_id, count in access['most_active']:
                    report += f"   • {patient_id}: {count} accesses\n"
        else:
            report += "   No access events\n"
        
        report += f"""
🛡️  PII PROTECTION
{'='*76}
"""
        
        if pii['total'] > 0:
            report += f"• Total PII Events: {pii['total']}\n"
            report += f"• Leaks Prevented: {pii['leaks_prevented']} 🚫\n\n"
            
            if pii['pii_types']:
                report += "PII Types Detected:\n"
                for pii_type, count in sorted(pii['pii_types'].items(), 
                                             key=lambda x: x[1], 
                                             reverse=True):
                    report += f"   • {pii_type}: {count}\n"
        else:
            report += "   ✅ No PII leakage detected\n"
        
        report += f"""
╔════════════════════════════════════════════════════════════════════════╗
║  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                        ║
║  Log Directory: {str(self.log_dir.absolute())[:50]:<50} ║
╚════════════════════════════════════════════════════════════════════════╝
"""
        
        return report


def main():
    """CLI per analisi log"""
    import sys
    
    analyzer = LogAnalyzer()
    
    if len(sys.argv) > 1:
        hours = int(sys.argv[1])
    else:
        hours = 24
    
    print(analyzer.generate_comprehensive_report(hours=hours))


if __name__ == "__main__":
    main()
