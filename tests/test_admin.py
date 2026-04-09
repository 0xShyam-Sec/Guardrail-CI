def test_status_endpoint(client):
    response = client.get("/admin/status")
    assert response.status_code == 200
    assert response.json()["status"] == "operational"
