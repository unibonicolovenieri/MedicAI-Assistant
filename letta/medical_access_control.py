"""
Schema per controllo accessi medici - GDPR compliant
"""
from enum import Enum
from typing import List, Optional
from pydantic import Field
from letta.schemas.letta_base import LettaBase


class MedicalRole(str, Enum):
    """Ruoli per accesso a dati medici"""
    PATIENT = "patient"  # Paziente - vede solo i propri dati
    DOCTOR = "doctor"  # Dottore - vede dati pazienti assegnati
    SECRETARY = "secretary"  # Segretario - gestisce appuntamenti, no dati clinici
    GUARD = "guard"  # Guardia - controlla login e attacchi


class DataSensitivityLevel(str, Enum):
    """Livelli di sensibilità dei dati"""
    PUBLIC = "public"  # Es: nome, cognome
    RESTRICTED = "restricted"  # Es: data appuntamento
    CONFIDENTIAL = "confidential"  # Es: diagnosi, terapie
    CRITICAL = "critical"  # Es: patologie gravi, dati genetici


class MedicalAccessPolicy(LettaBase):
    """Policy di accesso per dati medici"""
    
    patient_id: str = Field(..., description="ID del paziente proprietario dei dati")
    authorized_roles: List[MedicalRole] = Field(..., description="Ruoli autorizzati")
    authorized_user_ids: List[str] = Field(default_factory=list, description="Utenti specifici autorizzati")
    data_sensitivity: DataSensitivityLevel = Field(..., description="Livello di sensibilità")
    requires_explicit_consent: bool = Field(default=False, description="Richiede consenso esplicito")
    audit_access: bool = Field(default=True, description="Log degli accessi")
    

class MedicalContextFilter(LettaBase):
    """Filtro per contesto medico in base al ruolo"""
    
    role: MedicalRole = Field(..., description="Ruolo richiedente")
    user_id: str = Field(..., description="ID utente richiedente")
    patient_id: Optional[str] = Field(None, description="ID paziente (se ruolo è PATIENT)")
    
    def can_access_clinical_data(self) -> bool:
        """Verifica se il ruolo può accedere a dati clinici"""
        return self.role in [MedicalRole.DOCTOR, MedicalRole.PATIENT]
    
    def can_manage_appointments(self) -> bool:
        """Verifica se il ruolo può gestire appuntamenti"""
        return self.role in [MedicalRole.DOCTOR, MedicalRole.SECRETARY]
    
    def can_view_patient_list(self) -> bool:
        """Verifica se può vedere lista pazienti"""
        return self.role in [MedicalRole.DOCTOR, MedicalRole.SECRETARY]
