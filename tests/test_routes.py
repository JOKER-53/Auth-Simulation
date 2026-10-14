def test_index_route(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"OAuth Token Replay Attack Simulation" in response.data

def test_login_flow(client):
    # GET login page
    response = client.get('/login')
    assert response.status_code == 200
    assert b"Simulated Google Sign-In" in response.data

    # POST valid login
    response = client.post('/login', data={'email': 'student1@gmail.com'}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Welcome, Student One" in response.data
    assert b"Your Active Bearer Token" in response.data

def test_login_invalid_email(client):
    response = client.post('/login', data={'email': 'attacker@evil.com'})
    assert response.status_code == 401
    assert b"Unauthorized account" in response.data

def test_access_route_with_query_token(client, engine):
    token = engine.issue_token("student1@gmail.com")
    response = client.get(f'/access?token={token.token_id}')
    assert response.status_code == 200
    assert b"Student One" in response.data
    assert b"3.94" in response.data

def test_access_route_with_auth_header_and_json(client, engine):
    token = engine.issue_token("student2@gmail.com")
    response = client.get('/access', headers={
        'Authorization': f'Bearer {token.token_id}',
        'Accept': 'application/json'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['valid'] is True
    assert data['user']['name'] == "Student Two"
    assert data['user']['department'] == "Cybersecurity & Information Assurance"

def test_replay_attack_vulnerable_vs_secure(client, engine):
    token = engine.issue_token("student1@gmail.com")

    # Step 1: Legitimate initial access consumes token once
    res1 = client.get(f'/access?token={token.token_id}')
    assert res1.status_code == 200

    # Step 2: In vulnerable mode, replay attack should succeed
    engine.set_mode("vulnerable")
    res_replay_vuln = client.post('/replay', data={
        'token': token.token_id,
        'attacker_ip': '198.51.100.99'
    })
    assert res_replay_vuln.status_code == 200
    assert b"REPLAY ATTACK SUCCEEDED" in res_replay_vuln.data

    # Step 3: Switch to secure mode
    engine.set_mode("secure")
    new_token = engine.issue_token("student2@gmail.com")
    client.get(f'/access?token={new_token.token_id}')

    # Replay in secure mode must fail
    res_replay_sec = client.post('/replay', data={
        'token': new_token.token_id,
        'attacker_ip': '198.51.100.99'
    })
    assert res_replay_sec.status_code == 200
    assert b"REPLAY ATTACK BLOCKED" in res_replay_sec.data

def test_admin_and_api_status(client):
    response = client.get('/api/status')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'online'
    assert 'mode' in data
