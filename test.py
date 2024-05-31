import requests
import base64
from urllib.parse import urlencode
import time
api_token = "sktsec_b1q-gQvQXJMR0ZtfzPgmQx_PZNRhxEsxJUoOMK7rYhzM_api"
token = f"{api_token}:"
encoded_token = base64.b64encode(token.encode()).decode('ascii')

url = 'https://api.socket.dev/v0/orgs/socketdev-demo/full-scans'
params = {
    'repo': 'new-local-test',
    'branch': 'test'
}
full_url = f"{url}?{urlencode(params)}"
headers = {
    'Accept': 'application/json',
    'Authorization': f'Basic {encoded_token}'
}
key = 'requirements.txt'
files = []
file = (
    key,
    (
        key,
        open(key, 'rb')
    )
)
files.append(file)

resp = requests.post(full_url, headers=headers, files=files)

print(resp.status_code)
print(resp.text)

time.sleep(10)