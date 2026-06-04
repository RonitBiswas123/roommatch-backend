from pydantic import BaseModel
from typing import Optional

# ── User models ──
class UserRegister(BaseModel):
    name:     str
    email:    str
    password: str
    branch:   str
    year:     int
    gender:   str

class UserLogin(BaseModel):
    email:    str
    password: str

class UserResponse(BaseModel):
    id:     int
    name:   str
    email:  str
    branch: str
    year:   int
    gender: str

# ── Profile models ──
class ProfileCreate(BaseModel):
    sleep_time:   str
    wake_time:    str
    study_hours:  str
    cleanliness:  str
    noise:        str
    guests:       str
    about:        Optional[str] = ""