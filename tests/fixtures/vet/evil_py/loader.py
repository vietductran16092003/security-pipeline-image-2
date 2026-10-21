import base64

payload = "cHJpbnQoJ2hlbGxvJyk="
exec(base64.b64decode(payload))
