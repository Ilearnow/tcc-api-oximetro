from fastapi import FastAPI, Depends, HTTPException, status, Request, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
from typing import Optional


from app import models, schemas, auth
from app.database import engine, get_db
from app.config import settings 

if os.getenv("SSL_ENABLED", "false").lower() == "true":
    certs_dir = Path("certs")
    if not (certs_dir / "server.crt").exists():
        print("Os certificados não foram encontrados. Executando gerador")
        import subprocess

        subprocess.run(["python", "scripts/init-certs.py"], check=True)
    print(f"Certificados encontrados: {(certs_dir / 'server.crt').exists()}")

app = FastAPI(
    title="TCC - Oximeter API",
    description="API para coleta e consulta de leituras de oxímetro",
    version="1.0"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.get("/mtls-info")
async def get_mtls_info(
        request: Request,
        x_ssl_client_cn: Optional[str] = Header(None, alias="X-SSL-Client-CN"),
        x_ssl_client_verify: Optional[str] = Header(None, alias="X-SSL-Client-Verify"),
        x_device_certificate: Optional[str] = Header(None, alias="X-Device-Certificate")
):
    client_host = request.client.host if request.client else "unknown"

    return {
        "mtls_enabled": True,
        "client_ip": client_host,
        "client_certificate": x_ssl_client_cn,
        "verification_status": x_ssl_client_verify,
        "device_certificate": x_device_certificate,
        "authentication_method": "mutual_tls",
        "security_level": "medical_device_grade",
        "compliance": ["LGPD", "ANVISA "]
    }



async def log_mtls_audit(
        device_id: str,
        client_cert: str,
        client_ip: str,
        spo2: float,
        bpm: int
):
    logger.info(f"Leitura recebida via mTLS")
    logger.info(f"Certificado: {client_cert}")
    logger.info(f"Dispositivo: {device_id}")
    logger.info(f"IP Cliente: {client_ip}")
    logger.info(f"Dados: SpO2={spo2}%, BPM={bpm}")


def create_audit_log(
        db: Session,
        user_id: int = None,
        device_id: str = None,
        action: str = "",
        status: str = "",
        details: str = ""
):
    log = models.AuditLog(
        user_id=user_id,
        device_id=device_id,
        action=action,
        status=status,
        details=details
    )

    try:
        db.add(log)
        db.commit()
        db.refresh(log)

        if log.record_hash and log.record_hash == log.calculate_hash():
            logger.info(f"AUDIT LOG: {action} - {status} - Hash: {log.record_hash[:16]}...")
        else:
            logger.warning(f"AUDIT LOG HASH MISMATCH: {action}")

        return log

    except Exception as e:
        db.rollback()
        logger.error(f"FAILED TO CREATE AUDIT LOG: {str(e)}")
        logger.error(f"AUDIT FAILED: {action} - {status} - {details}")
        raise


@app.get("/new-api", include_in_schema=True)
async def read_new_api():
    return {"message": "This should appear"}


@app.get("/security-info")
async def security_info():
    return {
        "architecture": "TLS termination at Nginx",
        "external": "HTTPS/TLS 1.3",
        "internal": "HTTP over private Docker network",
        "authentication": "JWT + Device HMAC",
        "compliance": "LGPD/Health Data Protection"
    }


@app.post("/login", response_model=schemas.Token)
def login(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):

    user = db.query(models.User).filter(
        models.User.username == form_data.username
    ).first()

    if not user:
        create_audit_log(
            db=db,
            action="LOGIN",
            status="FAILURE",
            details=f"Usuário não encontrado: {form_data.username}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )


    try:
        valid_password = auth.verify_password(form_data.password, user.password_hash)
    except Exception as e:
        create_audit_log(
            db=db,
            action="LOGIN",
            status="ERROR",
            details=f"Erro na verificação de senha: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno na verificação de credenciais"
        )

    if not valid_password:
        create_audit_log(
            db=db,
            action="LOGIN",
            status="FAILURE",
            details=f"Senha incorreta para: {form_data.username}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        create_audit_log(
            db=db,
            user_id=user.id,
            action="LOGIN",
            status="FAILURE",
            details=f"Usuário inativo tentou login: {user.username}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário inativo"
        )

    access_token = auth.create_jwt_token(username=user.username)

    create_audit_log(
        db=db,
        user_id=user.id,
        action="LOGIN",
        status="SUCCESS",
        details=f"Login bem-sucedido: {user.username}"
    )

    return {"access_token": access_token, "token_type": "bearer"}


def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):

    payload = auth.verify_jwt_token(token)
    username = payload.get("sub")

    user = db.query(models.User).filter(
        models.User.username == username
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário não encontrado"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário inativo"
        )

    return user


@app.post("/readings", response_model=schemas.ReadingResponse)
def create_reading(
        reading_data: schemas.ReadingCreate,  
        request: Request,
        x_device_certificate: Optional[str] = Header(None, alias="X-Device-Certificate"),
        x_mtls_authenticated: Optional[str] = Header(None, alias="X-mTLS-Authenticated"),
        db: Session = Depends(get_db)
):

    is_mtls = x_mtls_authenticated == "true" and x_device_certificate
    client_ip = request.client.host if request.client else "unknown"
    
    if settings.log_sensitive_data:
        logger.info(f"Leitura recebida via {'mTLS' if is_mtls else 'HTTP'}")
    else:
        logger.info(f"Leitura recebida via {'mTLS' if is_mtls else 'HTTP'} para dispositivo {reading_data.device_id[:8]}...")
    
    
    if is_mtls:
        create_audit_log(
            db=db,
            device_id=reading_data.device_id,
            action="POST_READING_MTLS",
            status="SUCCESS",
            details=f"Leitura recebida via mTLS (IP: {client_ip}, Cert: {x_device_certificate[:20]}...)"
        )
    else:
        create_audit_log(
            db=db,
            device_id=reading_data.device_id,
            action="POST_READING_NO_MTLS",
            status="WARNING",
            details=f"Leitura recebida sem mTLS (IP: {client_ip})"
        )

    device = db.query(models.Device).filter(
        models.Device.device_id == reading_data.device_id,
        models.Device.is_active == True
    ).first()

    if not device:
        create_audit_log(
            db=db,
            device_id=reading_data.device_id,
            action="POST_READING",
            status="UNAUTHORIZED",
            details=f"Dispositivo {reading_data.device_id} não encontrado ou inativo"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Dispositivo não autorizado"
        )

    patient = db.query(models.Patient).filter(
        models.Patient.patient_code == reading_data.patient_code
    ).first()

    if not patient:
        create_audit_log(
            db=db,
            device_id=reading_data.device_id,
            action="POST_READING",
            status="NOT_FOUND",
            details=f"Paciente {reading_data.patient_code} não encontrado"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Paciente não encontrado"
        )

    new_reading = models.Reading(
        device_id=reading_data.device_id,
        patient_id=patient.id,
        spo2=reading_data.spo2,
        bpm=reading_data.bpm,
        reading_timestamp=reading_data.reading_timestamp,
        signature=reading_data.signature
    )

    try:
        db.add(new_reading)
        db.commit()
        db.refresh(new_reading)

        create_audit_log(
            db=db,
            device_id=reading_data.device_id,
            action="POST_READING",
            status="SUCCESS",
            details=f"Leitura criada para paciente {patient.patient_code}: SpO2={reading_data.spo2}, BPM={reading_data.bpm}"
        )

        return {
            "id": new_reading.id,
            "device_id": new_reading.device_id,
            "patient_code": patient.patient_code,
            "spo2": new_reading.spo2,
            "bpm": new_reading.bpm,
            "reading_timestamp": new_reading.reading_timestamp,
            "created_at": new_reading.created_at
        }

    except Exception as e:
        db.rollback()
        create_audit_log(
            db=db,
            device_id=reading_data.device_id,
            action="POST_READING",
            status="ERROR",
            details=f"Erro ao criar leitura: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@app.get("/readings/{patient_code}", response_model=list[schemas.ReadingResponse])
def get_readings(
        patient_code: str,
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
):

    patient = db.query(models.Patient).filter(
        models.Patient.patient_code == patient_code
    ).first()

    if not patient:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            action="GET_READINGS",
            status="NOT_FOUND",
            details=f"Paciente {patient_code} não encontrado"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Paciente não encontrado"
        )

    if patient.doctor_id != current_user.id:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            action="GET_READINGS",
            status="UNAUTHORIZED",
            details=f"Usuário {current_user.username} tentou acessar paciente {patient_code} sem permissão"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Não autorizado a acessar os dados deste paciente"
        )

    readings = db.query(models.Reading).filter(
        models.Reading.patient_id == patient.id
    ).order_by(models.Reading.reading_timestamp.desc()).all()

    # Log de sucesso
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="GET_READINGS",
        status="SUCCESS",
        details=f"Usuário {current_user.username} acessou {len(readings)} leituras do paciente {patient_code}"
    )

    result = []
    for reading in readings:
        result.append({
            "id": reading.id,
            "device_id": reading.device_id,
            "patient_code": patient.patient_code,
            "spo2": reading.spo2,
            "bpm": reading.bpm,
            "reading_timestamp": reading.reading_timestamp,
            "created_at": reading.created_at
        })

    return result


@app.post("/devices/register", response_model=schemas.DeviceRegisterResponse)
def register_device(
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    import secrets
    import hashlib

    device_id = f"OXIM-{secrets.token_hex(4).upper()}"
    device_secret = secrets.token_urlsafe(32)
    secret_hash = hashlib.sha256(device_secret.encode()).hexdigest()

    new_device = models.Device(
        device_id=device_id,
        secret_hash=secret_hash,
        is_active=True,
        registered_by=current_user.id
    )

    try:
        db.add(new_device)
        db.commit()
        db.refresh(new_device)

        create_audit_log(
            db=db,
            user_id=current_user.id,
            action="DEVICE_REGISTER",
            status="SUCCESS",
            details=f"Novo dispositivo registrado: {device_id} pelo usuário {current_user.username}"
        )

        return {
            "device_id": device_id,
            "device_secret": device_secret,
            "message": "Guarde o secret com segurança. Não será mostrado novamente."
        }

    except Exception as e:
        db.rollback()
        create_audit_log(
            db=db,
            user_id=current_user.id,
            action="DEVICE_REGISTER",
            status="ERROR",
            details=f"Erro ao registrar dispositivo: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao registrar dispositivo"
        )


@app.get("/patients", response_model=list[schemas.PatientResponse])
def get_patients(
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    patients = db.query(models.Patient).filter(
        models.Patient.doctor_id == current_user.id
    ).all()

    return [
        {
            "patient_code": p.patient_code,
            "full_name": p.full_name,
            "id": p.id
        }
        for p in patients
    ]


@app.get("/audit/verify/{log_id}")
def verify_audit_log_integrity(
        log_id: int,
        db: Session = Depends(get_db)
):
    log = db.query(models.AuditLog).filter(models.AuditLog.id == log_id).first()

    if not log:
        raise HTTPException(status_code=404, detail="Log não encontrado")

    current_hash = log.record_hash
    calculated_hash = log.calculate_hash()
    is_valid = current_hash == calculated_hash

    return {
        "log_id": log.id,
        "action": log.action,
        "created_at": log.created_at,
        "current_hash": current_hash,
        "calculated_hash": calculated_hash,
        "is_valid": is_valid,
        "message": "Hash válido" if is_valid else "Hash inválido - possível adulteração"
    }


@app.get("/audit/verify-all")
def verify_all_audit_logs(
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Acesso negado")

    logs = db.query(models.AuditLog).all()
    results = []

    for log in logs:
        current_hash = log.record_hash
        calculated_hash = log.calculate_hash()
        is_valid = current_hash == calculated_hash

        results.append({
            "id": log.id,
            "action": log.action,
            "created_at": log.created_at,
            "is_valid": is_valid,
            "hash_match": current_hash == calculated_hash
        })

    valid_count = sum(1 for r in results if r["is_valid"])
    total_count = len(results)

    return {
        "total_logs": total_count,
        "valid_logs": valid_count,
        "invalid_logs": total_count - valid_count,
        "integrity_percentage": (valid_count / total_count * 100) if total_count > 0 else 0,
        "logs": results
    }


@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}


@app.get("/logs")
def get_audit_logs(
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso de administrador necessário"
        )

    logs = db.query(models.AuditLog).order_by(
        models.AuditLog.created_at.desc()
    ).limit(100).all()

    return logs

@app.get("/compliance/policy")
def get_retention_policy():
    try:
        return {
            "data_retention_days": settings.DATA_RETENTION_DAYS,
            "audit_log_retention_days": getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', settings.DATA_RETENTION_DAYS),
            "compliance_frameworks": getattr(settings, 'COMPLIANCE_FRAMEWORKS', ["LGPD", "ANVISA"]),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "contact": "suporte@tcc.com.br",
            "encryption_standard": "AES-256",
            "authentication_methods": ["JWT", "mTLS"],
            "audit_enabled": True
        }
    except Exception as e:
        # Log do erro
        print(f"Erro em /compliance/policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao obter política de conformidade: {str(e)}"
        )


@app.get("/")
def read_root():
    return {
        "message": "API TCC - Sistema de Monitoramento de oxímetro",
        "version": "1.0",
        "docs": "/docs",
        "health": "/health"
    }


for route in app.routes:
    print(f"{route.methods} {route.path}")

@app.on_event("startup")
async def startup_event():
    print("API iniciada — usando esquema gerenciado pelo banco (init.sql)")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)
