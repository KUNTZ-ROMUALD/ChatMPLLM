from __future__ import annotations

import secrets


class CsrfTokenError(Exception):
    pass

class CsrfSettings :
    cookie_name : str = "XSRF-TOKEN"
    header_name : str = "X-XSRF-TOKEN"

class CsrfTokenService :
    def __init__(self, settings : CsrfSettings ) -> None :
        self._settings = settings

    @property
    def cookie_name(self)->str:
        return self._settings.cookie_name

    @property
    def header_name(self) -> str:
        return self._settings.header_name

    def generate_token(self)->str:
        return secrets.token_urlsafe(32)

    def validate(self, cookie_token : str | None , header_token : str | None ) -> None :
        if cookie_token is None or header_token is None  :
            raise CsrfTokenError("CSRF token missing")
        if not secrets.compare_digest(cookie_token, header_token) :
            raise CsrfTokenError("CSRF token mismatch")


