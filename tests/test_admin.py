def test_debug_endpoint_exposes_env(client):
    response = client.get("/admin/debug")
    assert response.status_code == 200
    data = response.json()
    assert "environment" in data
    assert "python_version" in data
