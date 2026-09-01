from __future__ import annotations

from uuid import uuid4

import pytest

from app.core.security.tokens import JwtSettings, JwtTokenService, TokenInvalidError


@pytest.fixture
def jwt_service() -> JwtTokenService:
    return JwtTokenService(JwtSettings(secret_key="test-secret-key"))


def test_access_token_roundtrip(jwt_service: JwtTokenService) -> None:
    user_id = uuid4()
    token = jwt_service.create_access_token(user_id, "user")
    payload = jwt_service.decode_access_token(token)

    assert payload["sub"] == str(user_id)
    assert payload["token_type"] == "access"
    assert payload["role"] == "user"


def test_refresh_token_roundtrip(jwt_service: JwtTokenService) -> None:
    user_id = uuid4()
    token = jwt_service.create_refresh_token(user_id, "admin")
    payload = jwt_service.decode_refresh_token(token)

    assert payload["sub"] == str(user_id)
    assert payload["token_type"] == "refresh"


def test_access_token_rejected_as_refresh(jwt_service: JwtTokenService) -> None:
    token = jwt_service.create_access_token(uuid4(), "user")
    with pytest.raises(TokenInvalidError):
        jwt_service.decode_refresh_token(token)


def test_tampered_token_rejected(jwt_service: JwtTokenService) -> None:
    token = jwt_service.create_access_token(uuid4(), "user")
    tampered = token[:-4] + "abcd"
    with pytest.raises(TokenInvalidError):
        jwt_service.decode_access_token(tampered)