#!/usr/bin/env python3
"""
Script di test per verificare integrazione Letta AI
"""

import sys
from pathlib import Path

# Aggiungi root al path
sys.path.insert(0, str(Path(__file__).parent))

from database.letta_client import get_letta_db
from config.settings import settings
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_letta_connection():
    """Test 1: Verifica connessione Letta"""
    print("\n" + "="*70)
    print("TEST 1: Connessione Letta")
    print("="*70)
    
    letta = get_letta_db()
    
    if letta.is_available():
        print("Letta client connesso correttamente")
        return True
    else:
        print("Letta non disponibile")
        print("Avvia server: letta server")
        return False


def test_agent_creation():
    """Test 2: Creazione agente paziente"""
    print("\n" + "="*70)
    print("TEST 2: Creazione Agente Paziente")
    print("="*70)
    
    letta = get_letta_db()
    
    if not letta.is_available():
        print("Skipped - Letta non disponibile")
        return False
    
    try:
        # Crea agente test
        agent_id = letta._get_or_create_agent("TEST_PAZ999")
        
        if agent_id:
            print(f"Agente creato: {agent_id}")
            return True
        else:
            print("Errore creazione agente")
            return False
            
    except Exception as e:
        print(f"Errore: {e}")
        return False


def test_appointment_storage():
    """Test 3: Salvataggio appuntamento"""
    print("\n" + "="*70)
    print("TEST 3: Salvataggio Appuntamento")
    print("="*70)
    
    letta = get_letta_db()
    
    if not letta.is_available():
        print("Skipped - Letta non disponibile")
        return False
    
    try:
        test_appointment = {
            "id": 999,
            "patient_id": "TEST_PAZ999",
            "date": "2025-12-01",
            "time": "10:00",
            "type": "Test Visit",
            "doctor": "Dr. Test",
            "status": "confirmed"
        }
        
        result = letta.store_appointment("TEST_PAZ999", test_appointment)
        
        if result:
            print("Appuntamento salvato in Letta")
            print(f"   Data: {test_appointment['date']}")
            print(f"   Orario: {test_appointment['time']}")
            return True
        else:
            print("Errore salvataggio")
            return False
            
    except Exception as e:
        print(f"Errore: {e}")
        return False


def test_memory_search():
    """Test 4: Ricerca in memoria"""
    print("\n" + "="*70)
    print("TEST 4: Ricerca in Memoria")
    print("="*70)
    
    letta = get_letta_db()
    
    if not letta.is_available():
        print("Skipped - Letta non disponibile")
        return False
    
    try:
        result = letta.search_in_memory(
            patient_id="TEST_PAZ999",
            query="Quali sono i miei appuntamenti?"
        )
        
        print(f"Risposta Letta:\n{result}")
        return True
        
    except Exception as e:
        print(f"Errore: {e}")
        return False


def test_fallback_mechanism():
    """Test 5: Meccanismo fallback"""
    print("\n" + "="*70)
    print("TEST 5: Fallback MemoryDB")
    print("="*70)
    
    from tools.medical_tools import db
    
    # Test che il database di fallback esista
    if "PAZ001" in db.patients:
        print(f"Fallback database disponibile con {len(db.patients)} pazienti")
        print(f"   Paziente PAZ001: {db.patients['PAZ001']['name']}")
        print(f"   Appuntamenti: {len(db.appointments)} totali")
        return True
    else:
        print("Fallback database non funzionante")
        return False


def main():
    """Esegui tutti i test"""
    print("\n" + "="*35)
    print("LETTA AI INTEGRATION TESTS")
    print("="*35)
    
    results = {
        "Connessione": test_letta_connection(),
        "Creazione Agente": test_agent_creation(),
        "Salvataggio": test_appointment_storage(),
        "Ricerca Memoria": test_memory_search(),
        "Fallback": test_fallback_mechanism()
    }
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nRisultato: {passed}/{total} test passati")
    
    if passed == total:
        print("\nTutti i test passati! Sistema pronto.")
    elif results["Fallback"]:
        print("\nLetta non disponibile ma fallback funziona.")
        print("Avvia Letta per funzionalità complete: letta server")
    else:
        print("\nAlcuni test falliti. Controlla configurazione.")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
