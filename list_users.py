import os, psycopg2, psycopg2.extras
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path('.env'))
print(f"Connecting to: {os.getenv('POSTGRES_DB')} on {os.getenv('POSTGRES_HOST')}...")

try:
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST"),
        port=os.getenv("POSTGRES_PORT"),
        dbname=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD")
    )
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, email, name, role FROM lms_users")
    users = cur.fetchall()
    print(f"Found {len(users)} users:")
    for u in users:
        print(f" - {u['email']} ({u['role']})")
except Exception as e:
    print(f"Error: {e}")
