import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(
    host=os.getenv("POSTGRES_HOST"),
    port=os.getenv("POSTGRES_PORT"),
    dbname=os.getenv("POSTGRES_DB"),
    user=os.getenv("POSTGRES_USER"),
    password=os.getenv("POSTGRES_PASSWORD")
)

cur = conn.cursor()
tables = ["lms_users", "lms_courses", "lms_modules", "lms_sessions", "lms_notifications", "lms_learning_paths", "lms_quizzes", "lms_quiz_attempts"]

results = []
for table in tables:
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = %s);", (table,))
    exists = cur.fetchone()[0]
    results.append(f"{table}:{'OK' if exists else 'MISSING'}")

print("Verification Result: " + " | ".join(results))

cur.close()
conn.close()
