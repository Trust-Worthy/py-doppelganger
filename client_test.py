import requests
resp = requests.post("http://localhost:5000/test", json={"hello": "world"})
print(resp.status_code)
print(resp.text)  # See the raw response body

print(resp.status_code, resp.json())