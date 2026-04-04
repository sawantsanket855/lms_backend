import requests
from jose import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET')
ALGORITHM = 'HS256'

def create_access_token(data):
    data['exp'] = datetime.utcnow() + timedelta(minutes=60)
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

import psycopg2
import psycopg2.extras
conn = psycopg2.connect(
    host=os.getenv('POSTGRES_HOST'),
    port=os.getenv('POSTGRES_PORT'),
    dbname=os.getenv('POSTGRES_DB'),
    user=os.getenv('POSTGRES_USER'),
    password=os.getenv('POSTGRES_PASSWORD')
)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
cur.execute("SELECT id FROM lms_users WHERE role='admin' LIMIT 1")
admin_row = cur.fetchone()
admin_id = admin_row['id'] if admin_row else 'admin_user'

cur.execute("SELECT user_id FROM lms_session_progress LIMIT 1")
student_row = cur.fetchone()
student_id = student_row['user_id'] if student_row else 'dummy_student'

cur.close()
conn.close()

token = create_access_token({'sub': admin_id})

headers = {'Authorization': f'Bearer {token}'}
url = f'http://127.0.0.1:8000/api/admin/student/{student_id}/analytics'
print(f'Fetching: {url}')

try:
    response = requests.get(url, headers=headers)
    print(f'Status Code: {response.status_code}')
    print('Response:', response.text[:500])
except Exception as e:
    print('Request failed:', e)
