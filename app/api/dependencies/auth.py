from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import HTTPException,status, Request
from fastapi.params import Depends, Cookie, Header
from sqlalchemy.orm import Session


from app.core.database import  get_db
from app.core.security.tokens import JwtTokenService, JwtSettings
from app.core.config import settings
from app.models.user import User

from app.core.security.csrf import CsrfTokenService, CsrfSettings, CsrfTokenError
from app.repositories.user_repository import SqlAlchemyUserRepository
from app.core.security import Pbkdf2PasswordHasher
from app.core.security.tokens import TokenExpiredError, TokenError
from app.schemas.auth import AuthUserEnvelope, AuthUserRead
from app.services.auth_service import AuthService

ACCESS_COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"

@dataclass(frozen=True, slots= True)
class AuthCookieSettings :
    access_cookie_name : str = ACCESS_COOKIE_NAME
    refresh_cookie_name : str = REFRESH_COOKIE_NAME
    access_cookie_path : str = "/"
    refresh_cookie_path : str = "/api/v1/auth"
    csrf_cookie_path : str = "/"

def get_jwt_service() -> JwtTokenService :
    secret_key = getattr(settings,"jwt_secret_key",None)
    if not isinstance(secret_key,str) or not secret_key :
        raise RuntimeError("jwt_secret_key missing")
    return JwtTokenService(
        JwtSettings(
            secret_key = secret_key,
        )
    )

def get_csrf_service() -> CsrfTokenService :
    return CsrfTokenService(CsrfSettings())

def get_auth_service(db : Annotated[Session, Depends(get_db)]) -> AuthService :
    user_repository = SqlAlchemyUserRepository(db)
    password_hasher = Pbkdf2PasswordHasher()
    return AuthService(user_repository, password_hasher)

def get_current_user (jwt_service : Annotated[JwtTokenService, Depends(get_jwt_service)],
                      db : Annotated[Session, Depends(get_db)],
                      access_token : Annotated[str | None, Cookie(alias=ACCESS_COOKIE_NAME)]=None,
                      ) -> User :
    if access_token is None :
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    try :
        payload = jwt_service.decode_access_token(access_token)
    except TokenExpiredError as exc :
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        ) from exc
    except TokenError as exc :
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail = "Not authenticated",
        ) from exc
    user_repository =SqlAlchemyUserRepository(db)
    user= user_repository.get_by_id(UUID(payload["sub"]))
    if user is None or not user.is_activate:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user

def get_csrf_header_token(
        csrf_token : Annotated[str | None , Header(alias="X-XSRF-TOKEN")] = None,
) -> str | None :
    return csrf_token

def enforce_csrf(
        request : Request,
        csrf_service : Annotated[CsrfTokenService, Depends(get_csrf_service)],
)-> None :
    cookie_token = request.cookies.get(csrf_service.cookie_name)
    header_token = request.headers.get(csrf_service.header_name)
    try :
        csrf_service.validate(cookie_token, header_token)
    except CsrfTokenError as exc :
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail = "CSRF validation failed",
        ) from exc

def auth_user_envelope(user : User) -> AuthUserEnvelope :
    return AuthUserEnvelope(
        user = AuthUserRead.model_validate(user),
    )





