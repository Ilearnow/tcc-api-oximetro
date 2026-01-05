from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text, event
from sqlalchemy.sql import func
from .database import Base
import json
from sqlalchemy.dialects.postgresql import JSONB

class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "core"}

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)
    full_name = Column(String(100))
    email = Column(String(100))
    specialty = Column(String(50))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True))



class Patient(Base):
    __tablename__ = "patients"
    __table_args__ = {'schema': 'core'}

    id = Column(Integer, primary_key=True, index=True)
    patient_code = Column(String(20), unique=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    date_of_birth = Column(DateTime)
    doctor_id = Column(Integer, ForeignKey('core.users.id'))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = {'schema': 'core'}

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(100), unique=True, nullable=False)
    secret_hash = Column(String(255))
    public_key = Column(Text)
    is_active = Column(Boolean, default=True)
    registered_by = Column(Integer, ForeignKey('core.users.id'))
    created_at = Column(DateTime(timezone=True))
    last_used_at = Column(DateTime(timezone=True))



class Reading(Base):
    __tablename__ = "readings"
    __table_args__ = {'schema': 'core'}

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(100), nullable=False)
    patient_id = Column(Integer, ForeignKey('core.patients.id'))

    spo2 = Column(Float, nullable=False)
    bpm = Column(Integer, nullable=False)
    reading_timestamp = Column(DateTime(timezone=True), nullable=False)

    signature = Column(String(255))
    metadata_json = Column(
        "metadata",
        JSONB,
        nullable=True
    )

    created_at = Column(DateTime(timezone=True))

    __decrypted_data = None

    @property
    def completed_data (self):
        if self.__decrypted_data is None and self.encrypted_data:
            from .security import decifrar_aes
            try:
                dados = {
                    'cifrado': self.encrypted_data,
                    'salt': self.salt,
                    'iv': self.iv
                }
                dados_str = decifrar_aes(dados)
                self.__decrypted_data = json.loads(dados_str)
            except Exception:
                self.__decrypted_data = {}
        return self.__decrypted_data

    @completed_data.setter
    def completed_data(self, value):
        if isinstance(value, dict):
            from .security import cifrar_aes, gerar_assinatura
            dados_str = json.dumps(value, ensure_ascii=False)

            crypted = cifrar_aes(dados_str)

            self.encrypted_data = crypted['cifrado']
            self.salt = crypted['salt']
            self.iv = crypted['iv']
            self.signature = gerar_assinatura(dados_str)

            self.__decrypted_data = value
        elif value is None:
            self.encrypted_data = None
            self.salt = None
            self.iv = None
            self.signature = None
            self.__decrypted_data = None


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = {'schema': 'audit'}

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('core.users.id'), nullable=True)
    device_id = Column(String(50), nullable=True)
    action = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False)
    details = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    record_hash = Column(String(64), nullable=True)

    def calculate_hash(self):
        import hashlib
        from datetime import datetime

        if self.created_at is None:
            self.created_at = datetime.utcnow()

        data = f"{self.user_id or ''}{self.device_id or ''}{self.action}{self.status}-{self.details or ''}{self.created_at}"
        return hashlib.sha256(data.encode('utf-8')).hexdigest()


@event.listens_for(AuditLog, 'before_insert')
def calculate_audit_hash_before_insert(mapper, connection, target):
    target.record_hash = target.calculate_hash()


def cifer_signature(mapper, connection, target):
    if target.encrypted_data is None:
        dados_extras = {
            "spo2": target.spo2,
            "bpm": target.bpm,
            "device_id": target.device_id,
            "reading_timestamp": target.reading_timestamp.isoformat() if target.reading_timestamp else None,
            "signature": target.signature if target.signature else ""
        }
        target.dados_completos = dados_extras


event.listen(Reading, 'before_insert', cifer_signature)
event.listen(Reading, 'before_update', cifer_signature)