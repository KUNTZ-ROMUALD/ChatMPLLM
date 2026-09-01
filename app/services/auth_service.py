from __future__ import annotations

from datetime import datetime, timezone
from uuid import  uuid4, UUID

from app.core.security import PasswordHasher
from app.models.user import UserRole, User
from app.repositories.user_repository import UserRepository
from app.schemas.auth import AuthRegisterRequest, AuthLoginRequest
from app.services.exceptions import EmailAlreadyExistsError, InvalidCredentialsError, UserNotFoundError


class AuthService :
    def __init__(self,user_repository: UserRepository, password_hasher : PasswordHasher) -> None:
        self._user_repository = user_repository
        self._password_hasher = password_hasher

    def register(self, data : AuthRegisterRequest):
        existing_user = self._user_repository.get_by_email(data.email)
        if existing_user is not None :
            raise EmailAlreadyExistsError("Email already exists")

        hashed_password = self._password_hasher.hash(data.password)
        user = User(
            id=uuid4(),
            email=data.email,
            hashed_password=hashed_password,
            display_name=data.display_name,
            role=UserRole.USER,
            created_at=datetime.now(timezone.utc),
        )
        return self._user_repository.create(user)

    def login(self, data : AuthLoginRequest):
        user= self._user_repository.get_by_email(data.email)

        if user is None :
            raise InvalidCredentialsError("Invalid credentials")

        if not self._password_hasher.verify(data.password, user.hashed_password) :
            raise InvalidCredentialsError("Invalid credentials")
        return user

    def get_me(self, user_id : UUID):
        user = self._user_repository.get_by_id(user_id)
        if user is None :
            raise UserNotFoundError("User not found")
        return user

    def refresh(self, user_id : UUID):
        return self.get_me(user_id)


