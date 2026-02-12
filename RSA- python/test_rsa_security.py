import pytest
import json
import base64
from rsa_service import app, init_db, get_db_connection
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['DATABASE'] = 'test_rsa_service.db'
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client
    # Cleanup
    if os.path.exists('test_rsa_service.db'):
        os.remove('test_rsa_service.db')

def register_user(client, username, password):
    return client.post('/api/register', json={
        'username': username,
        'password': password
    })

def login_user(client, username, password):
    return client.post('/api/login', json={
        'username': username,
        'password': password
    })

def test_unauthorized_decryption_prevention(client):
    """
    SECURE SDLC DEMONSTRATION: Verifies that Horizontal Privilege Escalation is prevented.
    User A should NOT be able to decrypt User B's file.
    """
    # 1. Register users with secure passwords (12+ chars)
    register_user(client, 'user_a', 'SecurePassword123!')
    register_user(client, 'user_b', 'SecurePassword456!')
    
    # 2. Login User B and upload a file
    login_b = login_user(client, 'user_b', 'SecurePassword456!')
    token_b = login_b.get_json()['token']
    
    with open('secret_b.txt', 'wb') as f:
        f.write(b"User B's secret content")
    
    upload_resp = client.post('/api/upload', 
                             data={'file': (open('secret_b.txt', 'rb'), 'secret_b.txt')},
                             headers={'Authorization': f'Bearer {token_b}'})
    file_id = upload_resp.get_json()['file_id']
    
    # 3. Login User A and try to decrypt User B's file
    login_a = login_user(client, 'user_a', 'SecurePassword123!')
    token_a = login_a.get_json()['token']
    
    # Even if User A has a private key, the server should block access to User B's file record
    decrypt_resp = client.post(f'/api/decrypt/{file_id}', 
                              json={'private_key': 'dummy_key'},
                              headers={'Authorization': f'Bearer {token_a}'})
    
    # Should be 404 (Not Found) or 403 (Forbidden) because the record isn't found for THIS user_id
    assert decrypt_resp.status_code == 404

def test_strong_password_validation(client):
    """
    SECURE SDLC DEMONSTRATION: Verifies that weak passwords are rejected.
    """
    resp = register_user(client, 'weak_user', '12345678') # Still too short (< 12)
    assert resp.status_code == 400
    assert "Minimum 12 characters" in resp.get_json()['error']

def test_private_key_safety(client):
    """
    SECURE SDLC DEMONSTRATION: Verifies that private keys are not leaked in public responses.
    """
    resp = register_user(client, 'safe_user', 'SecurePassword123!')
    data = resp.get_json()
    assert 'private_key' not in data, "SECURITY FAILURE: Private key leaked in registration!"
    assert 'public_key' in data
