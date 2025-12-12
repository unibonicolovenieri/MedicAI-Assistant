#!/usr/bin/env python3
"""Test Ollama con CrewAI"""

import os
os.environ["OPENAI_API_BASE"] = "http://localhost:11434/v1"
os.environ["OPENAI_MODEL_NAME"] = "llama3.2"
os.environ["OPENAI_API_KEY"] = "ollama"

from crewai import Agent, Task, Crew

# Agente semplice
agent = Agent(
    role="Test Agent",
    goal="Rispondere a domande semplici",
    backstory="Sei un assistente di test",
    verbose=True
)

# Task semplice
task = Task(
    description="Rispondi alla domanda: Qual è la capitale d'Italia?",
    expected_output="Nome della città",
    agent=agent
)

# Crew
crew = Crew(agents=[agent], tasks=[task], verbose=True)

print("\n🚀 Starting test...\n")
result = crew.kickoff()
print(f"\n✅ Result: {result}\n")
