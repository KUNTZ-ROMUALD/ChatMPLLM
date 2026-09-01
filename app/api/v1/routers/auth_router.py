from __future__ import annotations

from fastapi import APIRouter, Response, HTTPException,status
from fastapi.params import Depends
from sqlalchemy.sql.functions import current_user

from app.api.dependencies.auth import (
    ACCESS_COOKIE_NAME,
    REFRESH_COOKIE_NAME,
    get_csrf_service,
    enforce_csrf,
    get_auth_service,
    get_jwt_service,
    auth_user_envelope, get_current_user,
)
from app.core.security.csrf import CsrfTokenService
from app.core.security.tokens import JwtTokenService
from app.models.user import User
from app.schemas.auth import AuthRegisterRequest, AuthUserEnvelope, AuthLoginRequest, AuthMeResponse
from app.services.auth_service import AuthService
from app.services.exceptions import EmailAlreadyExistsError, InvalidCredentialsError

router = APIRouter(prefix="/auth", tags=["auth"])

def _set_auth_cookies(
        response : Response,
        jwt_service : JwtTokenService,
        csrf_service : CsrfTokenService,
        user : User )-> str :
    access_token = jwt_service.create_access_token(user.id,user.role.value)
    refresh_token = jwt_service.create_refresh_token(user.id, user.role.value)
    csrf_token = csrf_service.generate_token()

    response.set_cookie(
        key = ACCESS_COOKIE_NAME,
        value = access_token,
        httponly = True,
        secure = True,
        samesite = 'lax',
        path="/"
    )
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value = refresh_token,
        httponly = False,
        secure = False,
        samesite = "lax",
        path="/api/v1/auth"
    )
    response.set_cookie(
        key= csrf_service.cookie_name,
        value = csrf_token,
        httponly = False,
        secure = False,
        samesite = "lax",
        path="/"
    )
    return csrf_token

def _clear_auth_cookies(response : Response,csrf_service : CsrfTokenService,) -> None :
    response.delete_cookie(key=ACCESS_COOKIE_NAME, path="/")
    response.delete_cookie(key=REFRESH_COOKIE_NAME, path="/api/v1/auth")
    response.delete_cookie(key=csrf_service.cookie_name, path="/")

@router.get("/csrf")
def get_csrf_token(
    response: Response,
    csrf_service: CsrfTokenService = Depends(get_csrf_service),
) -> dict[str, str]:
    token = csrf_service.generate_token()
    response.set_cookie(
        key=csrf_service.cookie_name,
        value=token,
        httponly=False,
        secure=False,
        samesite="lax",
        path="/",
    )
    return {"csrf_token": token}

@router.post("/register",status_code=status.HTTP_201_CREATED)
def register(
        payload : AuthRegisterRequest,
        response : Response,
        _: None =  Depends(enforce_csrf),
        auth_service : AuthService =  Depends(get_auth_service),
        jwt_service : JwtTokenService = Depends(get_jwt_service),
        csrf_service : CsrfTokenService = Depends(get_csrf_service),
) -> AuthUserEnvelope :
    try :
        user = auth_service.register(payload)
    except EmailAlreadyExistsError as exc :
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail="Email already exists"
        ) from exc

    _set_auth_cookies(response,jwt_service,csrf_service,user)
    return auth_user_envelope(user)

@router.post("/login")
def login(
        payload : AuthLoginRequest,
        response : Response,
        _:None = Depends(enforce_csrf),
        auth_service : AuthService = Depends(get_auth_service),
        jwt_service : JwtTokenService = Depends(get_jwt_service),
        csrf_service : CsrfTokenService = Depends(get_csrf_service),
)->AuthUserEnvelope :
    try :
        user = auth_service.login(payload)
    except InvalidCredentialsError as exc :
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail= "Invalid credentials"
        ) from exc
    _set_auth_cookies(response, jwt_service, csrf_service,user)
    return auth_user_envelope(user)
@router.post("/logout")
def logout(
         response : Response,
        current_user : User = Depends(get_current_user),
        _:None = Depends(enforce_csrf),
        csrf_service : CsrfTokenService = Depends(get_csrf_service),
)-> dict[str, str] :
    _ = current_user
    _clear_auth_cookies(response, csrf_service)
    return {"detail":"Logged out"}

@router.post("/refresh")
def refresh(
        response : Response,
        _:None = Depends(enforce_csrf),
        auth_service : AuthService = Depends(get_auth_service),
        jwt_service : JwtTokenService = Depends(get_jwt_service),
        csrf_service : CsrfTokenService = Depends(get_csrf_service),) -> AuthUserEnvelope :
    raise HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail ="Not authenticated"
    )
@router.get("/me",response_model=AuthMeResponse)
def me(current_user : User = Depends(get_current_user)) ->AuthMeResponse :
    return AuthMeResponse.model_validate(current_user)












