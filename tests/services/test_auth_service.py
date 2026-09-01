from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.models.user import User, UserRole
from app.schemas.auth import AuthRegisterRequest, AuthLoginRequest
from app.services.auth_service import AuthService
from app.services.exceptions import EmailAlreadyExistsError, InvalidCredentialsError, UserNotFoundError


@dataclass
class InMemoryUserRepository:
    users_by_email : dict[str, User]
    users_by_id : dict[UUID, User]

    def get_by_email(self, email : str)-> User | None  :
        return self.users_by_email.get(email)

    def get_by_id(self, user_id : UUID)-> User | None :
        return self.users_by_id.get(user_id)

    def create(self, user : User) -> User:

        now = datetime.now(timezone.utc)
        if user.id is None :
            user.id = uuid4()
        user.created_at = now
        user.update_at = now
        self.users_by_email[user.email] = user
        self.users_by_id[user.id] = user
        return user

class FakePasswordHasher :
    def hash(self, password : str)-> str :
        return f"hashed:{password}"

    def verify(self, password : str, hashed_password : str)-> bool :
        return hashed_password == f"hashed:{password}"


def test_auth_service_register_hashes_password_and_creates_user()-> None:
    repository = InMemoryUserRepository(users_by_email ={},users_by_id= {})
    hasher = FakePasswordHasher()
    service = AuthService(repository, hasher)

    user = service.register(AuthRegisterRequest (
        email = "usermail@exemple.com",
        password = "secret-password",
        display_name = "Jane Doe",
        )
    )

    assert user.email == "usermail@exemple.com"
    assert user.display_name == "Jane Doe"
    assert user.role == UserRole.USER
    assert user.hashed_password == "hashed:secret-password"
    assert repository.get_by_email("usermail@exemple.com") == user


def test_auth_service_register_raises_when_email_already_exists() -> None :
    existing_user= User (
        id = uuid4(),
        email = "usermail@exemple.com",
        display_name = "Jane Doe",
        hashed_password = "hashed:secret-password",
        role = UserRole.USER,
    )

    repository = InMemoryUserRepository(
       users_by_email = {"usermail@exemple.com": existing_user},
        users_by_id= {existing_user.id: existing_user}
    )

    service = AuthService(repository, FakePasswordHasher())
    with pytest.raises(EmailAlreadyExistsError) :
        service.register(
            AuthRegisterRequest (
                email = "usermail@exemple.com",
                password = "secret-password",
                display_name="Jane Doe"
            )
        )
def test_auth_service_login_returns_user_when_credentials_are_valid() -> None:
    existing_user = User(
        id=uuid4(),
        email="user@example.com",
        hashed_password="hashed:secret-password",
        display_name="Jane Doe",
        role=UserRole.ADMIN,
    )
    repository = InMemoryUserRepository(
        users_by_email={"user@example.com": existing_user},
        users_by_id={existing_user.id: existing_user},
    )
    service = AuthService(repository, FakePasswordHasher())

    user = service.login(
        AuthLoginRequest(
            email="user@example.com",
            password="secret-password",
        )
    )

    assert user == existing_user


def test_auth_service_login_raises_invalid_credentials_when_user_is_missing() -> None:
    repository = InMemoryUserRepository(users_by_email={}, users_by_id={})
    service = AuthService(repository, FakePasswordHasher())

    with pytest.raises(InvalidCredentialsError, match="Invalid credentials"):
        service.login(
            AuthLoginRequest(
                email="user@example.com",
                password="secret-password",
            )
        )


def test_auth_service_login_raises_invalid_credentials_when_password_is_invalid() -> None:
    existing_user = User(
        id=uuid4(),
        email="user@example.com",
        hashed_password="hashed::secret-password",
        display_name="Jane Doe",
        role=UserRole.USER,
    )
    repository = InMemoryUserRepository(
        users_by_email={"user@example.com": existing_user},
        users_by_id={existing_user.id: existing_user},
    )
    service = AuthService(repository, FakePasswordHasher())

    with pytest.raises(InvalidCredentialsError, match="Invalid credentials"):
        service.login(
            AuthLoginRequest(
                email="user@example.com",
                password="wrong-password",
            )
        )


def test_auth_service_get_me_returns_user_when_user_exists() -> None:
    existing_user = User(
        id=uuid4(),
        email="user@example.com",
        hashed_password="hashed::secret-password",
        display_name="Jane Doe",
        role=UserRole.USER,
    )
    repository = InMemoryUserRepository(
        users_by_email={"user@example.com": existing_user},
        users_by_id={existing_user.id: existing_user},
    )
    service = AuthService(repository, FakePasswordHasher())

    user = service.get_me(existing_user.id)

    assert user == existing_user


def test_auth_service_get_me_raises_when_user_is_missing() -> None:
    repository = InMemoryUserRepository(users_by_email={}, users_by_id={})
    service = AuthService(repository, FakePasswordHasher())

    with pytest.raises(UserNotFoundError, match="User not found"):
        service.get_me(uuid4())


def test_auth_service_refresh_returns_user_when_user_exists() -> None:
    existing_user = User(
        id=uuid4(),
        email="user@example.com",
        hashed_password="hashed::secret-password",
        display_name="Jane Doe",
        role=UserRole.USER,
    )
    repository = InMemoryUserRepository(
        users_by_email={"user@example.com": existing_user},
        users_by_id={existing_user.id: existing_user},
    )
    service = AuthService(repository, FakePasswordHasher())

    user = service.refresh(existing_user.id)

    assert user == existing_user






