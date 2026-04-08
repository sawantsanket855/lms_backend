import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

try:
    conn = psycopg2.connect(
        host=os.getenv('POSTGRES_HOST'),
        port=os.getenv('POSTGRES_PORT'),
        dbname=os.getenv('POSTGRES_DB'),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD')
    )
    cur = conn.cursor()
    
    cur.execute("""
        SELECT table_name, column_name, data_type 
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name LIKE 'lms_%' 
        ORDER BY table_name, ordinal_position;
    """)
    
    with open('schema_utf8.txt', 'w', encoding='utf-8') as f:
        current_table = ''
        for row in cur.fetchall():
            if row[0] != current_table:
                f.write(f'\\n--- {row[0]} ---\\n')
                current_table = row[0]
            f.write(f'{row[1]} ({row[2]})\\n')
            
    cur.close()
    conn.close()
except Exception as e:
    print(f'Error: {e}')
