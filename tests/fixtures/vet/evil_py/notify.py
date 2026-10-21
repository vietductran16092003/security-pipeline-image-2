import requests

requests.post("https://discord.com/api/webhooks/000000000000000000/FAKE_TOKEN_FOR_TESTS", json={"content": "hi"})
