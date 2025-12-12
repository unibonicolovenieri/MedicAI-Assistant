"""
Client Ollama per interpretazione linguaggio naturale
"""
import requests
import json
from typing import Dict, Optional
from datetime import datetime, timedelta


class OllamaClient:
    """Client per Ollama API locale"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.model = "llama3.2:latest"
    
    def interpret_appointment_request(self, query: str, patient_name: str) -> Optional[Dict]:
        """
        Usa Ollama per interpretare richieste di appuntamento in linguaggio naturale
        
        Returns:
            Dict con 'date', 'time', 'type' se riconosciuta, None altrimenti
        """
        
        today = datetime.now().strftime('%Y-%m-%d')
        
        prompt = f"""Sei un assistente medico. Il paziente {patient_name} ha fatto questa richiesta:
"{query}"

Oggi è {today}.

Se la richiesta riguarda la PRENOTAZIONE di un appuntamento, estrai:
1. DATA (formato YYYY-MM-DD) - interpreta "domani", "oggi", "dopodomani", ecc.
2. ORA (formato HH:MM)
3. TIPO di visita (es: "controllo routine", "analisi sangue", "vaccinazione", "visita specialistica", "ecg", "consulto medico")

Rispondi SOLO in formato JSON:
{{"intent": "book_appointment", "date": "YYYY-MM-DD", "time": "HH:MM", "type": "tipo visita"}}

Se NON è una richiesta di prenotazione, rispondi:
{{"intent": "other"}}

Rispondi SOLO con il JSON, nient'altro."""

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3  # Bassa per risposte più deterministiche
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                response_text = result.get('response', '').strip()
                
                # Pulisci la risposta da eventuali markdown
                if '```json' in response_text:
                    response_text = response_text.split('```json')[1].split('```')[0].strip()
                elif '```' in response_text:
                    response_text = response_text.split('```')[1].split('```')[0].strip()
                
                # Parse JSON
                data = json.loads(response_text)
                
                if data.get('intent') == 'book_appointment':
                    return {
                        'date': data.get('date'),
                        'time': data.get('time'),
                        'type': data.get('type', 'Consulto medico')
                    }
            
            return None
            
        except Exception as e:
            print(f"⚠️  Ollama error: {e}")
            return None
    
    def generate_response(self, query: str, context: str = "") -> str:
        """
        Genera risposta usando Ollama per domande generiche
        """
        prompt = f"""Sei un assistente medico virtuale chiamato MedicAI.

{context}

Domanda del paziente: {query}

Rispondi in modo professionale, empatico e conciso. Usa emoji appropriate (🏥📋👨‍⚕️).
Se non sai qualcosa, suggerisci di contattare lo studio medico."""

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.7
                },
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', '').strip()
            
            return "Mi dispiace, al momento non riesco a elaborare la richiesta."
            
        except Exception as e:
            print(f"⚠️  Ollama error: {e}")
            return "Servizio AI temporaneamente non disponibile."
    
    def is_available(self) -> bool:
        """Verifica se Ollama è disponibile"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False


# Singleton globale
_ollama_client = None

def get_ollama_client() -> OllamaClient:
    """Factory per client Ollama"""
    global _ollama_client
    if _ollama_client is None:
        _ollama_client = OllamaClient()
    return _ollama_client
