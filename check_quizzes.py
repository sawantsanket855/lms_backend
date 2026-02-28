import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

# Connect to DB
conn = psycopg2.connect(
    host=os.getenv("POSTGRES_HOST"),
    port=os.getenv("POSTGRES_PORT"),
    dbname=os.getenv("POSTGRES_DB"),
    user=os.getenv("POSTGRES_USER"),
    password=os.getenv("POSTGRES_PASSWORD")
)

cur = conn.cursor(cursor_factory=RealDictCursor)

def check_quizzes():
    try:
        cur.execute("SELECT * FROM quizzes")
        quizzes = cur.fetchall()
        print(f"Total quizzes found: {len(quizzes)}")
        for q in quizzes:
            print(f"ID: {q['id']}, Title: {q['title']}, Session ID: {q['session_id']}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    check_quizzes()
