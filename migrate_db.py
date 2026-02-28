import os
import json
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

def migrate():
    try:
        print("Starting migration...")
        
        # 1. Create new modules table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS modules (
                id TEXT PRIMARY KEY,
                course_id TEXT REFERENCES courses(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                order_index INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("Created modules table.")

        # 2. Extract JSONB modules from courses and insert into new modules table
        # Only do this if courses has a 'modules' column
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='courses' AND column_name='modules'")
        if cur.fetchone():
            cur.execute("SELECT id, modules FROM courses")
            courses = cur.fetchall()
            modules_inserted = 0
            for course in courses:
                cid = course["id"]
                # some modules might be strings, some dicts based on how they were saved
                mods = course.get("modules")
                if not mods: continue
                if isinstance(mods, str):
                    try:
                        mods = json.loads(mods)
                    except:
                        continue
                
                if isinstance(mods, list):
                    for idx, m in enumerate(mods):
                        mid = m.get("id") or f"{cid}-m{idx}"
                        title = m.get("title", f"Module {idx+1}")
                        # Check if exists
                        cur.execute("SELECT id FROM modules WHERE id=%s", (mid,))
                        if not cur.fetchone():
                            cur.execute("""
                                INSERT INTO modules (id, course_id, title, order_index)
                                VALUES (%s, %s, %s, %s)
                            """, (mid, cid, title, m.get("order", idx)))
                            modules_inserted += 1

            print(f"Migrated {modules_inserted} modules from JSON to relational table.")

            # 3. Drop modules and category columns from courses
            cur.execute("ALTER TABLE courses DROP COLUMN IF EXISTS modules")
            cur.execute("ALTER TABLE courses DROP COLUMN IF EXISTS category")
            print("Dropped deprecated columns from courses.")
        else:
            print("courses.modules column does not exist, skipping JSON migration.")

        # 4. Create quiz_attempts table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id TEXT PRIMARY KEY,
                quiz_id TEXT,
                user_id TEXT,
                score INTEGER,
                passed BOOLEAN,
                responses JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("Created quiz_attempts table.")

        # 5. Add session_id to quizzes
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='quizzes' AND column_name='session_id'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE quizzes ADD COLUMN session_id TEXT")
            print("Added session_id to quizzes.")

        # 6. Delete old progress table, ensure session_progress exists.
        cur.execute("DROP TABLE IF EXISTS progress")
        print("Dropped legacy progress table.")

        conn.commit()
        print("Migration complete successfully.")

    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    migrate()
