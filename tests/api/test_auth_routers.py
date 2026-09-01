from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import auth as auth_dependencies

from app.api.v1.routers import auth_router
from app.models.user import UserRole
from app.schemas.auth import AuthRegisterRequest, AuthLoginRequest
from app.models.user import User
from app.services.exceptions import EmailAlreadyExistsError, InvalidCredentialsError
from app.core.security.csrf import CsrfTokenError


@dataclass
class FakeAuthService :
    users_by_email : dict[str, User]

    def register(self, payload : AuthRegisterRequest )-> User :
        if payload.email in self.users_by_email :
            raise EmailAlreadyExistsError("Email already exists")
        user = User(
            id = uuid4(),
            email = payload.email,
            hashed_password= "hashed-password",
            display_name = payload.display_name,
            role = UserRole.USER
        )
        now = datetime.now(timezone.utc)
        user.created_at = now
        user.update_at = now
        self.users_by_email[payload.email] = user
        return user

    def login(self, payload : AuthLoginRequest) -> User :

        user =  self.users_by_email.get(payload.email)
        if user is None or payload.password != "secret-password":
            raise InvalidCredentialsError("Invalid credentials")
        return user

    def get_me(self, user_id):
        for user in self.users_by_email.values():
            if user.id == user_id :
                return user
        raise InvalidCredentialsError("Invalid credentials")

    def refresh(self, user_id):
        return self.get_me(user_id)

class FakeJwtService :
    def create_access_token(self, user_id, role : str) -> str:
        return f"access::{user_id}::{role}"

    def create_refresh_token(self,user_id , role : str)-> str:
        return f"refresh::{user_id}::{role}"

    def decode_access_token(self,token : str) :
        _, user_id, role = token.split("::")
        return { }

class FakeCsrfService :
    cookie_name = "XSRF-TOKEN"
    header_name = "X-XSRF-TOKEN"

    def generate_token (self)-> str :
        return "csrf-token"

    def validate(self, cookie_token :str | None , header_token : str | None ) -> None :
        if cookie_token != "csrf-token" or header_token != "csrf-token" :
            raise CsrfTokenError("Invalid csrf")

@pytest.fixture()
def app()-> FastAPI :
    application = FastAPI()
    application.include_router(auth_router, prefix="/api/v1")
    return application

@pytest.fixture()
def client(app : FastAPI) -> TestClient:
    return TestClient(app)

@pytest.fixture()
def fake_user()-> User :
    now = datetime.now(timezone.utc)
    user = User(
        id = uuid4(),
        email="user@exemple.com",
        hashed_password="hashed-password",
        display_name="Jane Doe",
        role = UserRole.USER
    )
    user.created_at = now
    user.update_at = now
    return user

@pytest.fixture()
def fake_auth_service(fake_user : User)-> FakeAuthService   :
    return FakeAuthService(users_by_email={fake_user.email : fake_user})

@pytest.fixture(autouse=True)
def override_dependencies(
        app : FastAPI,
        fake_auth_service : FakeAuthService )-> None :
    app.dependency_overrides[auth_dependencies.get_auth_service]= lambda : fake_auth_service
    app.dependency_overrides[auth_dependencies.get_jwt_service] = lambda : FakeJwtService()
    app.dependency_overrides[auth_dependencies.get_csrf_service] = lambda : FakeCsrfService()
    yield
    app.dependency_overrides.clear()

@pytest.fixture()
def authenticated(app: FastAPI, fake_user: User) -> User:
    app.dependency_overrides[auth_dependencies.get_current_user] = lambda: fake_user
    return fake_user

def test_get_csrf_returns_token(client: TestClient) -> None:
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200
    assert response.json() == {"csrf_token": "csrf-token"}

def test_register_sets_auth_cookies_and_request_user(client : TestClient) -> None:
    client.cookies.set("XSRF-TOKEN", "csrf-token")

    response = client.post(
        "/api/v1/auth/register",
        headers={"X-XSRF-TOKEN": "csrf-token"},
        json={
            "email": "new-user@exemple.com",
            "password": "secret-password",
            "display_name": "New user",
        }
    )
    assert  response.status_code == 201
    assert response.json()["user"]["email"] == "new-user@exemple.com"
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies
    assert "XSRF-TOKEN" in response.cookies
def test_register_rejects_duplicate_email(client: TestClient,fake_user : User) -> None:
    client.cookies.set("XSRF-TOKEN", "csrf-token")
    response = client.post(
        "/api/v1/auth/register",
        headers={"X-XSRF-TOKEN": "csrf-token"},
        json={
            "email" : fake_user.email,
            "password" : "secret-password",
            "display_name": "Jane Doe",
        }
    )

    assert response.status_code == 400
    assert response.json() == {"detail":"Email already exists"}


def test_login_sets_auth_cookies_and_returns_user(client: TestClient ) -> None :
    client.cookies.set("XSRF-TOKEN", "csrf-token")

    response = client.post(
        "/api/v1/auth/login",
        headers={"X-XSRF-TOKEN": "csrf-token"},
        json={
            "email": "user@exemple.com",
            "password": "secret-password",
        },
    )

    assert response.status_code == 200
    assert response.json()["user"]["email"] == "user@exemple.com"
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

def test_login_rejects_invalid_credentials(client: TestClient) -> None:
    client.cookies.set("XSRF-TOKEN", "csrf-token")

    response = client.post(
        "/api/v1/auth/login",
        headers={"X-XSRF-TOKEN": "csrf-token"},
        json={
            "email": "user@exemple.com",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}

def test_mutation_rejects_without_csrf(client : TestClient) -> None :
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email" : "user@exemple.com",
            "password" : "secret-password"
        },
    )
    assert response.status_code == 403

def test_me_returns_current_user_when_authenticated(client: TestClient,authenticated: User) -> None:


    response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json()["email"] == "user@exemple.com"

def test_me_rejects_missing_auth(client: TestClient) -> None:
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}

def test_logout_clears_cookies_when_authenticated(client: TestClient,authenticated: User) -> None:

    client.cookies.set("XSRF-TOKEN", "csrf-token")

    response = client.post(
        "/api/v1/auth/logout",
        headers={"X-XSRF-TOKEN": "csrf-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "Logged out"}
    assert "access_token" not in response.cookies