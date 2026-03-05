import requests
import sys

def test_upload(base_url, token, file_path):
    url = f"{base_url}/api/media/upload"
    headers = {"Authorization": f"Bearer {token}"}
    
    with open(file_path, "rb") as f:
        files = {"file": (file_path.split("/")[-1], f, "image/jpeg")}
        response = requests.post(url, headers=headers, files=files)
        
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        file_id = response.json()["id"]
        print(f"Upload successful. File ID: {file_id}")
        
        # Test retrieval
        get_url = f"{base_url}/api/media/{file_id}"
        get_resp = requests.get(get_url)
        print(f"Retrieval Status: {get_resp.status_code}")
        print(f"Content-Type: {get_resp.headers.get('Content-Type')}")
        
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python verify_upload.py <base_url> <token> <file_path>")
        sys.exit(1)
    test_upload(sys.argv[1], sys.argv[2], sys.argv[3])
