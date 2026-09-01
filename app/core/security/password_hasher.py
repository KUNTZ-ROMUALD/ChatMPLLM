from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Protocol


class PasswordHasher(Protocol):
    def hash(self, password: str)->str :
        ...

    def verify(self,password : str, hashed_password : str  )-> bool :
        ...

@dataclass(frozen=True, slots=True)
class Pbkdf2PasswordHasher :
    iterations: int  = 210_000
    salt_size : int = 16

    def hash(self, password : str ):
        salt = secrets.token_bytes(self.salt_size)
        devired_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.iterations,
        )
        return self._encode(self.iterations,salt,devired_key)

    def verify(self,password : str, hashed_password : str)-> bool:

        try :
            iterations,salt,stored_derived_key = self._decode(hashed_password)
        except ValueError :
            return False

        derived_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )
        return hmac.compare_digest(derived_key, stored_derived_key)
    def _encode(self,iterations : int , salt : bytes , derived_key : bytes) ->str:
        encode_salt = base64.urlsafe_b64encode(salt).decode("ascii")
        encode_derived_key = base64.urlsafe_b64encode(derived_key).decode("ascii")
        return f"pbkdf2_sha256&{iterations}&{encode_salt}&{encode_derived_key})"

    def _decode(self,hashed_password : str) ->tuple[int,bytes,bytes]:
        algorithm, iteration_str, encoded_salt, encoded_derived_key = hashed_password.split("&",
                                                                                            maxsplit=3,)
        if algorithm != "pbkdf2_sha256":
            raise ValueError("Unsupported password hash algorithm")
        iterations = int(iteration_str)
        salt = base64.urlsafe_b64decode(encoded_salt.encode("ascii"))
        derived_key = base64.urlsafe_b64decode(encoded_derived_key.encode("ascii"))
        return iterations, salt, derived_key






