"""
Service per gestione accessi medici con privacy GDPR-compliant
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import Session

from letta.log import get_logger
from letta.schemas.user import User
from letta.schemas.medical_access_control import (
    MedicalRole, 
    DataSensitivityLevel, 
    MedicalAccessPolicy,
    MedicalContextFilter
)
from letta.schemas.message import Message
from letta.orm import Message as MessageModel

logger = get_logger(__name__)


class MedicalAccessManager:
    """Gestisce il controllo accessi per dati medici sensibili"""
    
    def __init__(self):
        self.audit_log: List[Dict[str, Any]] = []
    
    def filter_messages_by_medical_access(
        self,
        messages: List[Message],
        context_filter: MedicalContextFilter,
        patient_id: Optional[str] = None
    ) -> List[Message]:
        """
        Filtra messaggi in base al ruolo medico dell'utente
        
        Args:
            messages: Lista messaggi da filtrare
            context_filter: Filtro con ruolo e ID utente
            patient_id: ID paziente (per verifica ownership)
            
        Returns:
            Lista messaggi filtrati secondo le policy di accesso
        """
        filtered = []
        
        for msg in messages:
            # Log accesso per audit
            self._log_access_attempt(
                user_id=context_filter.user_id,
                role=context_filter.role,
                message_id=msg.id,
                accessed_at=datetime.now(timezone.utc)
            )
            
            # Applica filtri basati su ruolo
            if self._can_access_message(msg, context_filter, patient_id):
                # Maschera dati sensibili se necessario
                filtered_msg = self._sanitize_message_for_role(msg, context_filter)
                filtered.append(filtered_msg)
        
        return filtered
    
    def _can_access_message(
        self,
        message: Message,
        context_filter: MedicalContextFilter,
        patient_id: Optional[str]
    ) -> bool:
        """Verifica se l'utente può accedere al messaggio"""
        
        # PATIENT: vede solo i propri dati
        if context_filter.role == MedicalRole.PATIENT:
            return message.user_id == context_filter.user_id
        
        # SECRETARY: NO dati clinici, solo appuntamenti
        if context_filter.role == MedicalRole.SECRETARY:
            return self._is_appointment_data(message) and not self._contains_clinical_data(message)
        
        # DOCTOR: vede pazienti assegnati
        if context_filter.role == MedicalRole.DOCTOR:
            return self._is_assigned_patient(context_filter.user_id, patient_id)
        
        # GUARD: solo log di sicurezza
        if context_filter.role == MedicalRole.GUARD:
            return self._is_security_log(message)
        
        return False
    
    def _sanitize_message_for_role(
        self,
        message: Message,
        context_filter: MedicalContextFilter
    ) -> Message:
        """Maschera informazioni sensibili in base al ruolo"""
        
        # SECRETARY: rimuovi dati clinici
        if context_filter.role == MedicalRole.SECRETARY:
            message = self._mask_clinical_data(message)
        
        return message
    
    def _mask_clinical_data(self, message: Message) -> Message:
        """Maschera dati clinici sensibili"""
        # Implementa logica per mascherare diagnosi, terapie, etc.
        # Es: sostituzione con [DATO CLINICO RISERVATO]
        
        import re
        from copy import deepcopy
        
        masked_message = deepcopy(message)
        
        # Pattern per identificare dati clinici
        clinical_patterns = [
            r'diagnosi[:\s]+[^\n]+',
            r'terapia[:\s]+[^\n]+',
            r'sintomi[:\s]+[^\n]+',
            r'farmaco[:\s]+[^\n]+',
        ]
        
        # Maschera nel contenuto del messaggio
        if masked_message.content:
            for content_block in masked_message.content:
                if hasattr(content_block, 'text'):
                    text = content_block.text
                    for pattern in clinical_patterns:
                        text = re.sub(pattern, '[DATO CLINICO RISERVATO]', text, flags=re.IGNORECASE)
                    content_block.text = text
        
        return masked_message
    
    def _is_appointment_data(self, message: Message) -> bool:
        """Verifica se il messaggio riguarda appuntamenti"""
        keywords = ['appuntamento', 'prenotazione', 'visita', 'orario', 'disponibilità']
        
        if message.content:
            for content_block in message.content:
                if hasattr(content_block, 'text'):
                    text = content_block.text.lower()
                    if any(kw in text for kw in keywords):
                        return True
        return False
    
    def _contains_clinical_data(self, message: Message) -> bool:
        """Verifica se contiene dati clinici"""
        clinical_keywords = [
            'diagnosi', 'terapia', 'farmaco', 'sintomo', 'patologia',
            'esame', 'analisi', 'referto', 'cartella clinica'
        ]
        
        if message.content:
            for content_block in message.content:
                if hasattr(content_block, 'text'):
                    text = content_block.text.lower()
                    if any(kw in text for kw in clinical_keywords):
                        return True
        return False
    
    def _is_assigned_patient(self, doctor_id: str, patient_id: Optional[str]) -> bool:
        """Verifica se il paziente è assegnato al dottore"""
        # Implementa logica di verifica assegnazione
        # Dovrebbe interrogare una tabella doctor_patient_assignments
        # Per ora return True (implementa la tua logica)
        return True
    
    def _is_security_log(self, message: Message) -> bool:
        """Verifica se è un log di sicurezza"""
        security_keywords = ['login', 'logout', 'tentativo', 'accesso', 'autenticazione']
        
        if message.content:
            for content_block in message.content:
                if hasattr(content_block, 'text'):
                    text = content_block.text.lower()
                    if any(kw in text for kw in security_keywords):
                        return True
        return False
    
    def _log_access_attempt(
        self,
        user_id: str,
        role: MedicalRole,
        message_id: str,
        accessed_at: datetime
    ):
        """Log degli accessi per audit GDPR"""
        audit_entry = {
            'user_id': user_id,
            'role': role.value,
            'message_id': message_id,
            'accessed_at': accessed_at.isoformat(),
            'action': 'read'
        }
        self.audit_log.append(audit_entry)
        
        logger.info(
            f"[AUDIT] User {user_id} ({role.value}) accessed message {message_id} at {accessed_at}"
        )
    
    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Recupera log audit per compliance GDPR"""
        filtered_log = self.audit_log
        
        if user_id:
            filtered_log = [e for e in filtered_log if e['user_id'] == user_id]
        
        if start_date:
            filtered_log = [
                e for e in filtered_log 
                if datetime.fromisoformat(e['accessed_at']) >= start_date
            ]
        
        if end_date:
            filtered_log = [
                e for e in filtered_log 
                if datetime.fromisoformat(e['accessed_at']) <= end_date
            ]
        
        return filtered_log


# Istanza globale
medical_access_manager = MedicalAccessManager()
