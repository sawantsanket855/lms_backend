import requests
import os
import time
import sys
from jose import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import psycopg2

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET')
ALGORITHM = 'HS256'

def create_access_token(uid):
    data = {'sub': uid, 'exp': datetime.utcnow() + timedelta(minutes=60)}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def generate_large_file(filename, size_mb):
    print(f"Generating {size_mb}MB file: {filename}...")
    with open(filename, "wb") as f:
        f.write(os.urandom(size_mb * 1024 * 1024))

def test_upload(base_url, file_path):
    # Get a valid admin ID from DB
    print("Connecting to DB to find an admin...")
    conn = psycopg2.connect(
        host=os.getenv('POSTGRES_HOST'),
        port=os.getenv('POSTGRES_PORT'),
        dbname=os.getenv('POSTGRES_DB'),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD')
    )
    cur = conn.cursor()
    cur.execute("SELECT id FROM lms_users WHERE role='admin' LIMIT 1")
    admin_row = cur.fetchone()
    cur.close()
    conn.close()

    if not admin_row:
        print("No admin user found in DB. Please register an admin first.")
        return

    admin_id = admin_row[0]
    token = create_access_token(admin_id)
    headers = {'Authorization': f'Bearer {token}'}
    
    url = f"{base_url}/api/media/upload"
    print(f"Uploading {file_path} to {url}...")
    
    start_time = time.time()
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f, "video/mp4")}
        try:
            response = requests.post(url, headers=headers, files=files, timeout=600)
            duration = time.time() - start_time
            print(f"Response Status: {response.status_code}")
            print(f"Time Taken: {duration:.2f} seconds")
            if response.status_code == 200:
                print("Upload Successful!")
                print(f"Response: {response.json()}")
            else:
                print(f"Upload Failed: {response.text}")
        except requests.exceptions.Timeout:
            print("Request timed out (client-side)!")
        except Exception as e:
            print(f"Request failed: {e}")

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    file_to_upload = "test_17mb.mp4"
    
    if not os.path.exists(file_to_upload):
        generate_large_file(file_to_upload, 17)
    
    test_upload(target_url, file_to_upload)
    
    # Optional: Clean up
    # os.remove(file_to_upload)
