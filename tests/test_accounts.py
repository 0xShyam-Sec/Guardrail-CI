from jose import jwt
from app.config import SECRET_KEY, ALGORITHM


def _get_auth_header(client, username="testuser", password="password123"):
    client.post("/auth/register", json={
        "username": username,
        "password": password,
    })
    response = client.post("/auth/login", json={
        "username": username,
        "password": password,
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_get_account_balance(client):
    headers = _get_auth_header(client)
    token = headers["Authorization"].split(" ")[1]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id = int(payload["sub"])

    response = client.get(f"/accounts/{user_id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["balance"] == 1000.0


def test_transfer_money(client):
    headers1 = _get_auth_header(client, "user1", "pass1")
    headers2 = _get_auth_header(client, "user2", "pass2")

    token1 = headers1["Authorization"].split(" ")[1]
    payload1 = jwt.decode(token1, SECRET_KEY, algorithms=[ALGORITHM])
    user1_id = int(payload1["sub"])

    token2 = headers2["Authorization"].split(" ")[1]
    payload2 = jwt.decode(token2, SECRET_KEY, algorithms=[ALGORITHM])
    user2_id = int(payload2["sub"])

    response = client.post(f"/accounts/{user1_id}/transfer", json={
        "to_account_id": user2_id,
        "amount": 250.0,
    }, headers=headers1)
    assert response.status_code == 200
    assert response.json()["message"] == "Transfer successful"

    # Check balances
    r1 = client.get(f"/accounts/{user1_id}", headers=headers1)
    r2 = client.get(f"/accounts/{user2_id}", headers=headers2)
    assert r1.json()["balance"] == 750.0
    assert r2.json()["balance"] == 1250.0


def test_transfer_insufficient_funds(client):
    headers = _get_auth_header(client)
    token = headers["Authorization"].split(" ")[1]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id = int(payload["sub"])

    response = client.post(f"/accounts/{user_id}/transfer", json={
        "to_account_id": 999,
        "amount": 99999.0,
    }, headers=headers)
    assert response.status_code == 400
