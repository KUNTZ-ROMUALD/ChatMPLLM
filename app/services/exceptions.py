from __future__ import annotations


class AuthError (Exception):
    pass

class EmailAlreadyExistsError(AuthError):
    pass

class InvalidCredentialsError (AuthError):
    pass

class UserNotFoundError(AuthError) :
    pass
