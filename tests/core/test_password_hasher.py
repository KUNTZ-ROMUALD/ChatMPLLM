import pytest

from app.core.security.password_hasher import Pbkdf2PasswordHasher


@pytest.fixture
def hasher () -> Pbkdf2PasswordHasher :
    return Pbkdf2PasswordHasher(iterations=1_000)

def test_hash_produces_verifiable_password(hasher):
    hashed = hasher.hash("MonMotDePasse123")
    assert hasher.verify("MonMotDePasse123",hashed) is True
def test_wrong_password_fails(hasher):
    hashed = hasher.hash("MonMotDePasse123")
    assert hasher.verify("MauvaisMotDePasse",hashed) is False

def test_hash_is_salted_differently_each_time(hasher):
    h1 = hasher.hash("MemeMotPasse")
    h2 = hasher.hash("MemeMotPasse")
    assert h1 != h2
    assert hasher.verify("MemeMotPasse",h1) is True
    assert hasher.verify("MemeMotPasse",h2) is True

def test_malformed_hash_returns_false(hasher):
    assert hasher.verify("peu importe","pas un hash valide") is False

def tests_unsupported_algorithm_returns_false(hasher):
    fake_hash = "argon2$10002sda==$zerzar=="
    assert hasher.verify("peu importe",fake_hash) is False


