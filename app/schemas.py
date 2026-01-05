from pydantic import BaseModel, field_validator, ConfigDict, Field
from datetime import datetime, timedelta
import re
from typing import Optional

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str
    role: str = "doctor"
    specialty: Optional[str] = None

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('A senha deve ter pelo menos 8 caracteres')
        if len(v.encode('utf-8')) > 4096:
            raise ValueError('Senha muito longa')
        if not any(c.isupper() for c in v):
            raise ValueError('A senha deve conter pelo menos uma letra maiúscula')
        if not any(c.isdigit() for c in v):
            raise ValueError('A senha deve conter pelo menos um número')
        return v

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError('Username pode conter apenas letras, números, ., - e _')
        return v


class ReadingCreate(BaseModel):
    device_id: str
    patient_code: str
    spo2: float
    bpm: int
    reading_timestamp: datetime
    signature: str = ""

    @field_validator('spo2')
    @classmethod
    def validate_spo2(cls, v: float) -> float:
        if v < 0 or v > 100:
            raise ValueError('SpO2 must be between 0 and 100')
        if v < 70:
            raise ValueError('SpO2 clinically low')
        return v

    @field_validator('bpm')
    @classmethod
    def validate_bpm(cls, v: int) -> int:
        if v < 30 or v > 250:
            raise ValueError('BPM outside viable range')
        return v

    @field_validator('reading_timestamp')
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        now = datetime.utcnow()
        if v > now:
            raise ValueError('Timestamp cannot be in the future')
        if v < now - timedelta(days=7):
            raise ValueError('Timestamp too old (max 7 days)')
        return v

    @field_validator('device_id')
    @classmethod
    def validate_device_id(cls, v: str) -> str:
        if not v.startswith('OXIM-'):
            raise ValueError('Device ID must start with OXIM-')

        if len(v) < 8 or len(v) > 13:
            raise ValueError('Device ID must be 8-13 characters (e.g., OXIM-002 or OXIM-403AA9A8)')

        suffix = v[5:]
        if not re.match(r'^[A-Za-z0-9]+$', suffix):
            raise ValueError('Device ID suffix must contain only alphanumeric characters')

        return v

    @field_validator('patient_code')
    @classmethod
    def validate_patient_code(cls, v: str) -> str:
        if len(v) == 11 and v.isdigit():
            return v
        elif v.startswith('COD-') and len(v) == 8:
            return v
        elif v.startswith('PAT-') and len(v) >= 8:
            return v
        else:
            raise ValueError('Invalid patient code format')


class ReadingResponse(BaseModel):
    id: int
    device_id: str
    patient_code: str
    spo2: float
    bpm: int
    reading_timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class DeviceRegisterResponse(BaseModel):
    device_id: str
    device_secret: str
    message: str


class PatientResponse(BaseModel):
    id: int
    patient_code: str
    full_name: str

    model_config = ConfigDict(from_attributes=True)