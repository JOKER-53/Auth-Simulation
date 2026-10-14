import time
from app.simulation import OAuthSimulationEngine

def test_issue_token_success():
    engine = OAuthSimulationEngine(mode="vulnerable", token_ttl=60)
    token = engine.issue_token("student1@gmail.com", client_ip="192.168.1.50")
    assert token is not None
    assert token.email == "student1@gmail.com"
    assert token.google_id == "google-uid-101"
    assert token.used_count == 0
    assert not token.is_revoked
    assert token.token_id in engine.tokens

def test_issue_token_unauthorized_user():
    engine = OAuthSimulationEngine()
    token = engine.issue_token("unknown@attacker.com")
    assert token is None

def test_vulnerable_mode_allows_replay():
    engine = OAuthSimulationEngine(mode="vulnerable", token_ttl=60)
    token = engine.issue_token("student1@gmail.com", client_ip="10.0.0.1")

    # Initial legitimate access
    is_valid_1, msg_1, user_1 = engine.verify_token(token.token_id, client_ip="10.0.0.1")
    assert is_valid_1 is True
    assert user_1.name == "Student One"
    assert token.used_count == 1

    # Attacker replays from different IP
    is_valid_2, msg_2, user_2 = engine.verify_token(token.token_id, client_ip="198.51.100.22", is_replay_test=True)
    assert is_valid_2 is True
    assert "VULNERABILITY EXPLOITED" in msg_2
    assert token.used_count == 2
    assert not token.is_revoked

def test_secure_mode_blocks_replay_and_revokes():
    engine = OAuthSimulationEngine(mode="secure", token_ttl=60)
    token = engine.issue_token("student2@gmail.com", client_ip="127.0.0.1")

    # Initial use is valid
    is_valid_1, msg_1, user_1 = engine.verify_token(token.token_id, client_ip="127.0.0.1")
    assert is_valid_1 is True
    assert token.used_count == 1

    # Replay attempt must be blocked and auto-revoked
    is_valid_2, msg_2, user_2 = engine.verify_token(token.token_id, client_ip="127.0.0.1", is_replay_test=True)
    assert is_valid_2 is False
    assert "Replay Attack Blocked" in msg_2
    assert token.is_revoked is True

    # Subsequent access attempt is also blocked
    is_valid_3, msg_3, user_3 = engine.verify_token(token.token_id, client_ip="127.0.0.1")
    assert is_valid_3 is False
    assert "Token revoked" in msg_3

def test_token_expiration():
    engine = OAuthSimulationEngine(mode="secure", token_ttl=1)
    token = engine.issue_token("student1@gmail.com", client_ip="127.0.0.1")
    time.sleep(1.2)

    is_valid, msg, user = engine.verify_token(token.token_id, client_ip="127.0.0.1")
    assert is_valid is False
    assert "expired" in msg.lower()
