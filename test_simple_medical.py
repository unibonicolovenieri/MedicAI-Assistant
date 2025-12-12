#!/usr/bin/env python3
"""Test Medical AI con Ollama - Versione Semplificata"""

import os
os.environ["OPENAI_API_BASE"] = "http://localhost:11434/v1"
os.environ["OPENAI_MODEL_NAME"] = "llama3.2"
os.environ["OPENAI_API_KEY"] = "ollama"

from crewai import Agent, Task, Crew
from tools.medical_tools import get_clinic_info

# Agente info (senza tool complessi)
info_agent = Agent(
    role="Medical Information Specialist",
    goal="Fornire informazioni pubbliche sullo studio medico",
    backstory="Fornisci informazioni su orari, servizi e contatti dello studio.",
    tools=[get_clinic_info],
    verbose=True
)

# Task semplice
task = Task(
    description="Rispondi: Quali sono gli orari dello studio?",
    expected_output="Orari di apertura dello studio",
    agent=info_agent
)

# Crew
crew = Crew(agents=[info_agent], tasks=[task], verbose=True)

print("\nTest Medical AI con Ollama...\n")
result = crew.kickoff()
print(f"\nRisposta:\n{result}\n")
