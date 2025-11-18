# test_setup.py
print("🔍 Verifico installazioni...\n")

try:
    import fastapi
    print("✅ FastAPI:", fastapi.__version__)
except ImportError:
    print("❌ FastAPI non installato")

try:
    import crewai
    print("✅ CrewAI:", crewai.__version__)
except ImportError:
    print("❌ CrewAI non installato")

try:
    import letta
    print("✅ Letta:", letta.__version__)
except ImportError:
    print("❌ Letta non installato")

try:
    import sqlalchemy
    print("✅ SQLAlchemy:", sqlalchemy.__version__)
except ImportError:
    print("❌ SQLAlchemy non installato")

try:
    import cryptography
    print("✅ Cryptography:", cryptography.__version__)
except ImportError:
    print("❌ Cryptography non installato")

print("\n✨ Setup completato!")