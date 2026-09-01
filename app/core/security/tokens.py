from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import timedelta, datetime,timezone

from typing import TypedDict, Any
from uuid import UUID


class TokenError(Exception) :
    pass

class TokenExpiredError(TokenError) :
    pass

class TokenInvalidError(TokenError) :
    pass

class TokenPayload(TypedDict) :
    sub : str
    token_type : str
    exp : int
    iat : int
    jti : str
    role : str

def _base64url_encode(data : bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _base64url_decode(data : str) -> bytes :
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))

def _json_dumps(value : dict[str, Any]) -> str:
    return json.dumps(value, separators=(',', ':'), sort_keys=True)

@dataclass(frozen=True, slots=True)
class JwtSettings :
    secret_key : str
    algorithms : str = "HS256"
    access_token_ttl_minutes : int  = 15
    refresh_token_ttl_days : int  = 7

class JwtTokenService :
    def __init__(self, settings : JwtSettings) -> None:
        self._settings = settings

    def create_access_token(self, user_id : UUID , role : str ):
        return self._encode_token(
            subject = user_id,
            token_type = "access",
            ttl = timedelta(minutes=self._settings.access_token_ttl_minutes),
            role = role
        )

    def create_refresh_token(self, user_id : UUID , role : str) ->str :
        return self._encode_token(
            subject = user_id,
            token_type = "refresh",
            ttl = timedelta(days=self._settings.refresh_token_ttl_days),
            role = role,
        )

    def decode_access_token(self,token: str)->TokenPayload:
        payload = self._decode_token(token)
        if payload["token_type"] != "access":
            raise TokenInvalidError("Invalid token type")
        return payload

    def decode_refresh_token(self, token: str)->TokenPayload:
        payload = self._decode_token(token)
        if payload["token_type"] != "refresh":
            raise TokenInvalidError("Invalid token type")
        return payload

    def _encode_token(self,
                      subject : UUID,
                      token_type : str,
                      ttl : timedelta,
                      role : str ) -> str:
        now = datetime.now(timezone.utc)
        payload : TokenPayload = {
            "sub" : str(subject),
            "token_type" : token_type,
            "exp" : int((now + ttl).timestamp()),
            "iat" : int(now.timestamp()),
            "role" : role,
            "jti" : secrets.token_hex(16)
        }
        header = { "alg" : self._settings.algorithms, "typ" : "JWT" }
        encoded_header = _base64url_encode(_json_dumps(header).encode("utf-8"))
        encoded_payload = _base64url_encode(_json_dumps(payload).encode("utf-8"))
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = hmac.new(
            self._settings.secret_key.encode("utf-8"),
            signing_input,
            hashlib.sha256,).digest()
        encoded_signature = _base64url_encode(signature)
        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    def _decode_token(self, token : str) -> TokenPayload:
        parts = token.split(".")
        if len(parts) != 3 :
            raise TokenInvalidError("Invalid token format ")
        encoded_header, encoded_payload, encoded_signature = parts
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected_signature = hmac.new(
            self._settings.secret_key.encode("UTF-8"),
            signing_input,
            hashlib.sha256,

        ).digest()

        if not hmac.compare_digest(_base64url_decode(encoded_signature), expected_signature) :
            raise TokenInvalidError("Invalid Token signature")
        try:
            payload_raw = _base64url_decode(encoded_payload).decode("utf-8")
            payload_dict = json.loads(payload_raw)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc :
            raise TokenInvalidError("Invalid token payload") from exc
        if not isinstance(payload_dict, dict) :
            raise TokenInvalidError("Invalid token payload")

        payload = payload_dict
        if not isinstance(payload.get("sub"), str) :
            raise TokenInvalidError("Invalid token subject")
        if not isinstance(payload.get("token_type"), str) :
            raise TokenInvalidError("Invalid token type")
        if not isinstance(payload.get("exp"), int) :
            raise TokenInvalidError("Invalid token expiration")
        if not isinstance(payload.get("iat"), int):
            raise TokenInvalidError("Invalid token issued-at")
        if not isinstance(payload.get("jti"), str) :
            raise TokenInvalidError("Invalid token id")
        if not isinstance(payload.get("role"), str) :
            raise TokenInvalidError("Invalid token role")

        now_ts = int( datetime.now(timezone.utc).timestamp() )
        if payload["exp"] < now_ts:
            raise TokenInvalidError("Token expired")
        return payload