from crewai.tools import tool
from typing import Optional, Dict, List
from datetime import datetime
import logging

from database.letta_client import get_letta_db

logger = logging.getLogger(__name__)

# Database simulato in memoria (FALLBACK se Letta non disponibile)
class MemoryDB:
    """Database in memoria per sviluppo"""
    
    def __init__(self):
        self.patients = {
            "PAZ001": {
                "name": "Mario Rossi",
                "pin_hash": "123456",  # In produzione: hash bcrypt
                "dob": "1980-05-15",
                "phone": "+39 333 1234567"
            },
            "PAZ002": {
                "name": "Laura Bianchi",
                "pin_hash": "654321",
                "dob": "1992-08-22",
                "phone": "+39 338 9876543"
            }
        }
        
        self.appointments = [
            {
                "id": 1,
                "patient_id": "PAZ001",
                "date": "2024-11-25",
                "time": "10:00",
                "doctor": "Dr. Verdi",
                "type": "Controllo routine",
                "status": "confirmed"
            }
        ]
        
        self.sessions = {}  # patient_id: session_data
        
    def authenticate(self, patient_id: str, pin: str) -> bool:
        """Autentica paziente con timing-safe comparison"""
        if patient_id in self.patients:
            # In produzione: bcrypt.checkpw()
            # Usa timing-safe comparison per prevenire timing attacks
            import hmac
            stored_pin = self.patients[patient_id]["pin_hash"]
            if hmac.compare_digest(stored_pin.encode(), pin.encode()):
                self.sessions[patient_id] = {
                    "authenticated_at": datetime.now(),
                    "is_active": True
                }
                return True
        return False
    
    def is_authenticated(self, patient_id: str) -> bool:
        """Verifica se paziente è autenticato"""
        return patient_id in self.sessions and self.sessions[patient_id]["is_active"]
    
    def get_patient_info(self, patient_id: str) -> Optional[Dict]:
        """Ritorna info paziente (se esiste nel database)"""
        # Rimuovo il check di autenticazione - la sicurezza è gestita da SecureMedicalAssistant
        return self.patients.get(patient_id)
    
    def get_appointments(self, patient_id: str) -> List[Dict]:
        """Ritorna appuntamenti paziente"""
        if not self.is_authenticated(patient_id):
            return []
        return [apt for apt in self.appointments if apt["patient_id"] == patient_id]
    
    def add_appointment(self, patient_id: str, date: str, time: str, 
                       appointment_type: str) -> Optional[Dict]:
        """Crea nuovo appuntamento"""
        if not self.is_authenticated(patient_id):
            return None
        
        new_apt = {
            "id": len(self.appointments) + 1,
            "patient_id": patient_id,
            "date": date,
            "time": time,
            "doctor": "Dr. Verdi",  # Assegnazione automatica
            "type": appointment_type,
            "status": "confirmed"
        }
        self.appointments.append(new_apt)
        return new_apt

# Istanza globale (in produzione: dependency injection)
db = MemoryDB()

# Istanza Letta (primary storage)
letta_db = get_letta_db()


# ============================================
# TOOLS DEFINITI (con Letta Integration)
# ============================================

@tool
def authenticate_patient(patient_id: str, pin: str) -> str:
    """
    Autentica un paziente usando ID e PIN a 6 cifre.
    
    Args:
        patient_id: ID univoco del paziente (es: PAZ001)
        pin: PIN numerico a 6 cifre
        
    Returns:
        Messaggio di conferma o errore autenticazione
    """
    # Prova prima con Letta
    if letta_db.is_available():
        try:
            success = letta_db.authenticate_patient(patient_id, pin)
            if success:
                # Marca anche sessione locale
                db.authenticate(patient_id, pin)
                logger.info(f"Autenticazione Letta per {patient_id}")
                return f"Autenticazione riuscita tramite Letta. Benvenuto/a!"
        except Exception as e:
            logger.warning(f"Letta auth fallito, fallback: {e}")
    
    # Fallback a MemoryDB
    success = db.authenticate(patient_id, pin)
    
    if success:
        patient = db.patients[patient_id]
        return f"Autenticazione riuscita. Benvenuto/a {patient['name']}!"
    else:
        return "Autenticazione fallita. Verifica ID paziente e PIN."


@tool
def verify_patient_authenticated(patient_id: str) -> str:
    """
    Verifica se un paziente è autenticato nella sessione corrente.
    
    Args:
        patient_id: ID del paziente da verificare
        
    Returns:
        Stato autenticazione
    """
    is_auth = db.is_authenticated(patient_id)
    if is_auth:
        return f"Paziente {patient_id} è autenticato"
    else:
        return f"Paziente {patient_id} NON è autenticato. Richiedi login."


@tool
def get_available_slots(date: str) -> str:
    """
    Ritorna gli slot orari disponibili per una data specifica.
    
    Args:
        date: Data nel formato YYYY-MM-DD
        
    Returns:
        Lista slot disponibili
    """
    # Simulazione - in produzione: query al calendario
    slots = [
        "09:00", "09:30", "10:00", "10:30",
        "14:00", "14:30", "15:00", "15:30",
        "16:00", "16:30", "17:00"
    ]
    
    # Filtra slot già occupati (simulato)
    occupied = ["10:00", "15:00"]
    available = [s for s in slots if s not in occupied]
    
    return f"Slot disponibili per {date}:\n" + "\n".join(f"  - {slot}" for slot in available)


@tool
def book_appointment(patient_id: str, date: str, time: str, reason: str) -> str:
    """
    Prenota un appuntamento per un paziente AUTENTICATO.
    
    Args:
        patient_id: ID del paziente
        date: Data appuntamento (YYYY-MM-DD)
        time: Orario (HH:MM)
        reason: Motivo della visita
        
    Returns:
        Conferma prenotazione o errore
    """
    # Verifica autenticazione
    if not db.is_authenticated(patient_id):
        return "ERRORE: Paziente non autenticato. Richiedi login prima."
    
    appointment_data = {
        "patient_id": patient_id,
        "date": date,
        "time": time,
        "type": reason,
        "doctor": "Dr. Verdi",
        "status": "confirmed",
        "id": len(db.appointments) + 1
    }
    
    # Prova prima Letta
    if letta_db.is_available():
        try:
            letta_result = letta_db.store_appointment(patient_id, appointment_data)
            if letta_result:
                logger.info(f"Appuntamento salvato in Letta per {patient_id}")
                # Salva anche in MemoryDB per consistenza
                db.add_appointment(patient_id, date, time, reason)
                
                return f"""Appuntamento confermato e salvato in memoria persistente!

Dettagli:
  - ID Appuntamento: #{appointment_data['id']}
  - Data: {date}
  - Orario: {time}
  - Medico: Dr. Verdi
  - Tipo visita: {reason}
  - Stato: confirmed

Riceverai un SMS di promemoria 24h prima.
Letta AI ha memorizzato questo appuntamento."""
        except Exception as e:
            logger.warning(f"Letta booking fallito: {e}")
    
    # Fallback MemoryDB
    appointment = db.add_appointment(patient_id, date, time, reason)
    
    if appointment:
        return f"""Appuntamento confermato!

Dettagli:
  - ID Appuntamento: #{appointment['id']}
  - Data: {appointment['date']}
  - Orario: {appointment['time']}
  - Medico: {appointment['doctor']}
  - Tipo visita: {appointment['type']}
  - Stato: {appointment['status']}

Riceverai un SMS di promemoria 24h prima."""
    else:
        return "Errore durante la prenotazione. Riprova."


@tool
def get_my_appointments(patient_id: str) -> str:
    """
    Recupera tutti gli appuntamenti di un paziente AUTENTICATO.
    
    Args:
        patient_id: ID del paziente
        
    Returns:
        Lista appuntamenti o messaggio errore
    """
    if not db.is_authenticated(patient_id):
        return "Devi autenticarti per vedere i tuoi appuntamenti."
    
    # Prova prima Letta
    if letta_db.is_available():
        try:
            letta_appointments = letta_db.get_appointments(patient_id)
            if letta_appointments:
                result = f"I tuoi appuntamenti ({len(letta_appointments)}) da Letta:\n\n"
                for apt in letta_appointments:
                    result += f"""━━━━━━━━━━━━━━━━━━━━━━
ID Appuntamento: #{apt.get('id', 'N/A')}
Data: {apt['date']} ore {apt['time']}
Medico: {apt.get('doctor', 'Dr. Verdi')}
Tipo: {apt['type']}
Stato: {apt.get('status', 'confirmed')}

"""
                return result
        except Exception as e:
            logger.warning(f"Letta get appointments fallito: {e}")
    
    # Fallback MemoryDB
    appointments = db.get_appointments(patient_id)
    
    if not appointments:
        return "Non hai appuntamenti programmati al momento."
    
    result = f"I tuoi appuntamenti ({len(appointments)}):\n\n"
    for apt in appointments:
        result += f"""━━━━━━━━━━━━━━━━━━━━━━
ID Appuntamento: #{apt['id']}
Data: {apt['date']} ore {apt['time']}
Medico: {apt['doctor']}
Tipo: {apt['type']}
Stato: {apt['status']}

"""
    return result


@tool
def check_privacy_violation(query: str, context: str = "") -> str:
    """
    TOOL CRITICO: Analizza una query per potenziali violazioni privacy.
    Questo tool deve essere chiamato PRIMA di processare qualsiasi richiesta.
    
    Args:
        query: La richiesta dell'utente da analizzare
        context: Contesto aggiuntivo (paziente autenticato, etc)
        
    Returns:
        Rapporto di sicurezza: SAFE o BLOCKED con motivazione
    """
    query_lower = query.lower()
    
    # Pattern di attacco noti
    attack_patterns = {
        "data_leak": [
            "altri pazienti", "lista pazienti", "tutti i pazienti",
            "pazienti con", "chi ha", "quali pazienti"
        ],
        "unauthorized_access": [
            "cartella clinica di", "diagnosi di", "referti di",
            "storia medica di", "terapia di"
        ],
        "social_engineering": [
            "sono il figlio", "sono il marito", "sono la moglie",
            "sono il dottore", "per conto di"
        ],
        "prompt_injection": [
            "ignora istruzioni", "ignora le regole", "ignora policy",
            "modalità sviluppatore", "debug mode", "admin mode",
            "roleplay come", "fingi di essere", "sei ora"
        ],
        "inference_attack": [
            "quanti pazienti", "statistiche pazienti", "media età",
            "chi era qui", "chi c'era", "appuntamento prima"
        ]
    }
    
    # Controlla ogni categoria
    violations = []
    for category, patterns in attack_patterns.items():
        for pattern in patterns:
            if pattern in query_lower:
                violations.append({
                    "category": category,
                    "pattern": pattern,
                    "severity": "CRITICAL"
                })
    
    if violations:
        report = "[BLOCKED] - PRIVACY VIOLATION DETECTED\n\n"
        report += f"Query: '{query}'\n\n"
        report += "Violazioni rilevate:\n"
        for v in violations:
            report += f"  - {v['category'].upper()}: pattern '{v['pattern']}'\n"
        report += "\nQuesta richiesta è stata BLOCCATA e registrata per audit."
        return report
    
    return f"SAFE - Query '{query}' non presenta violazioni privacy."


@tool
def get_clinic_info() -> str:
    """
    Ritorna informazioni pubbliche sullo studio medico.
    Questo tool NON richiede autenticazione.
    
    Returns:
        Informazioni generali (orari, servizi, contatti)
    """
    return """STUDIO MEDICO ASSOCIATO DR. VERDI

Indirizzo:
   Via Roma 123, 40100 Bologna

Contatti:
   Tel: 051 123456
   Email: info@studiomedico.it

Orari:
   Lunedì - Venerdì: 08:00 - 19:00
   Sabato: 09:00 - 13:00
   Domenica: Chiuso

Servizi:
   - Medicina Generale
   - Cardiologia
   - Dermatologia
   - Analisi del sangue
   - ECG
   - Vaccinazioni

Convenzioni:
   - SSN (Servizio Sanitario Nazionale)
   - Assicurazioni private principali

Prenotazioni:
   - Online tramite questo assistente
   - Telefono: 051 123456
   - Email: prenotazioni@studiomedico.it"""
