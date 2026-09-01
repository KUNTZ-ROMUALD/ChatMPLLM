from __future__ import annotations


from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict,EmailStr


from app.models.user import UserRole


class AuthRegisterRequest(BaseModel):
    email: EmailStr
    password : str =Field(min_length = 1 ,max_length = 255)
    display_name : str = Field(min_length = 1, max_length = 120)

class AuthLoginRequest(BaseModel):
    email: EmailStr
    password : str = Field(min_length = 1 ,max_length = 255)

class AuthUserRead(BaseModel) :
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id : UUID
    email : EmailStr
    display_name : str
    role : UserRole
    created_at : datetime

class AuthUserEnvelope(BaseModel) :
    user : AuthUserRead

class AuthMeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id : UUID
    email : EmailStr
    display_name : str
    role : UserRole
    created_at : datetime
    updated_at : datetime = Field(validation_alias="update_at")



    
