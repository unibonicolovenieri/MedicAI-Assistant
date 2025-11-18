# quick_test.py
import asyncio
from letta_client import Letta
from crewai import Agent, Task, Crew

async def test_setup():
    print("🧪 Test 1: Letta Connection")
    try:
        client = Letta(base_url="http://localhost:8283")
        print("✅ Letta client connesso")
    except Exception as e:
        print(f"❌ Errore Letta: {e}")
        return
    
    print("\n🧪 Test 2: CrewAI Agent")
    try:
        test_agent = Agent(
            role="Test Agent",
            goal="Verificare setup",
            backstory="Agente di test",
            verbose=False
        )
        
        test_task = Task(
            description="Rispondi: 'Setup completato con successo!'",
            agent=test_agent,
            expected_output="Conferma setup"
        )
        
        crew = Crew(
            agents=[test_agent],
            tasks=[test_task],
            verbose=False
        )
        
        result = crew.kickoff()
        print("✅ CrewAI funzionante")
        print(f"   Risposta: {result}")
        
    except Exception as e:
        print(f"❌ Errore CrewAI: {e}")
    
    print("\n✨ Tutti i test completati!")

if __name__ == "__main__":
    asyncio.run(test_setup())