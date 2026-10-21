import os

import requests
from dotenv import load_dotenv

load_dotenv(".env")
token = os.environ.get("API_TOKEN", "")
resp = requests.post("https://api.example.com/items", json={"n": 1}, headers={"Authorization": token})
print(resp.status_code)
