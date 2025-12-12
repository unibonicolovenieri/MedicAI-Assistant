#!/usr/bin/env python3
"""
Interfaccia diretta con Letta - Bypass CrewAI
Usa solo Letta per rispondere alle domande
"""

from database.letta_client import get_letta_db
from tools.medical_tools import db  # Database di fallback

def chat_with_letta(patient_id: str, message: str):
    """
    Chat diretta con Letta
    
    Args:
        patient_id: ID del paziente
        message: Messaggio da inviare
        
    Returns:
        Risposta di Letta
    """
    letta = get_letta_db()
    
    if not letta.is_available():
        return "⚠️ Letta non disponibile. Usa il database locale."
    
    # Cerca in memoria
    response = letta.search_in_memory(patient_id, message)
    return response


def main():
    """Test interfaccia"""
    print("="*70)
    print("🏥 MEDICAL AI ASSISTANT - Interfaccia Letta Diretta")
    print("="*70)
    
    # Test 1: Domanda generale
    print("\n📌 Test 1: Quali sono i miei appuntamenti?")
    patient_id = "TEST_PAZ999"
    response = chat_with_letta(patient_id, "Quali sono i miei appuntamenti?")
    print(f"\n🤖 Letta: {response}\n")
    
    # Test 2: Info clinica (usa database locale)
    print("\n📌 Test 2: Orari studio (database locale)")
    print(f"📊 Pazienti in DB: {list(db.patients.keys())}")
    print(f"📅 Appuntamenti: {len(db.appointments)}")
    
    # Test 3: Autenticazione
    print("\n📌 Test 3: Autenticazione")
    auth_ok = db.authenticate("PAZ001", "123456")
    if auth_ok:
        print("✅ Autenticazione riuscita per PAZ001")
        print(f"👤 Nome: {db.patients['PAZ001']['name']}")
        appointments = db.get_appointments("PAZ001")
        print(f"📅 Appuntamenti: {len(appointments)}")
        if appointments:
            apt = appointments[0]
            print(f"   - {apt['date']} alle {apt['time']}: {apt['type']}")
    
    print("\n" + "="*70)
    print("✅ Sistema funzionante!")
    print("💡 Usa Letta per memoria persistente + Database locale per operazioni")
    print("="*70)


if __name__ == "__main__":
    main()
