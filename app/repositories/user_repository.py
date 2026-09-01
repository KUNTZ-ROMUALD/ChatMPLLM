from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User


class UserRepository(Protocol) :
    def get_by_email(self, email : str )-> User | None :
        ...
    def get_by_id(self, user_id : UUID)-> User | None :
        ...
    def create(self,user : User)-> User :
        ...

class SqlAlchemyUserRepository :
    def __init__(self,session : Session):
        self._session = session

    def get_by_email(self, email : str)-> User | None :
        statement = select(User).where(User.email == email)
        return self._session.scalar(statement)

    def get_by_id(self, user_id : UUID)-> User | None :
        statement = select(User).where(User.id == user_id)
        return self._session.scalar(statement)
    def create(self, user : User ) -> User :
        self._session.add(user)
        self._session.commit()
        self._session.refresh(user)
        return user


