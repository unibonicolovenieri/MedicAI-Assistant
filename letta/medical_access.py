"""
Middleware per Letta Server che applica controllo accessi medico
"""
from typing import Callable
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from letta.log import get_logger
from letta.schemas.medical_access_control import MedicalRole, MedicalContextFilter
from letta.services.medical_access_manager import medical_access_manager

logger = get_logger(__name__)


class MedicalAccessMiddleware(BaseHTTPMiddleware):
    """
    Middleware che filtra richieste in base al ruolo medico
    
    Estrae header:
    - X-Medical-Role: ruolo medico (patient/doctor/secretary/guard)
    - X-Patient-ID: ID paziente (per verifica ownership)
    - user_id: ID utente richiedente
    
    Applica filtri prima di restituire dati sensibili
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Estrai header ruolo medico
        medical_role_str = request.headers.get("X-Medical-Role")
        patient_id = request.headers.get("X-Patient-ID")
        user_id = request.headers.get("user_id")
        
        # Se non c'è ruolo medico, passa la richiesta normalmente
        if not medical_role_str:
            return await call_next(request)
        
        # Valida ruolo medico
        try:
            medical_role = MedicalRole(medical_role_str)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Ruolo medico non valido: {medical_role_str}"
            )
        
        # Crea filtro di contesto
        context_filter = MedicalContextFilter(
            role=medical_role,
            user_id=user_id or "unknown",
            patient_id=patient_id
        )
        
        # Log accesso
        logger.info(
            f"[MEDICAL ACCESS] Role: {medical_role.value}, "
            f"User: {user_id}, Patient: {patient_id}, "
            f"Path: {request.url.path}"
        )
        
        # Salva filtro nella request state per uso downstream
        request.state.medical_context_filter = context_filter
        
        # Processa richiesta
        response = await call_next(request)
        
        return response
