import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException
import os
import bcrypt
from app.config import settings

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("Senha muito curta")

    pepper = os.getenv("PEPPER_KEY", "")

    if pepper:
        password =  password + pepper

    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:

    if not plain_password or not hashed_password:
        return False

    pepper = os.getenv("PEPPER_KEY", "")
    if pepper:
        plain_password = plain_password + pepper

    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except (ValueError, TypeError):
        print(f"Erro ao verificar senha (hash inválido?)")
        return False


def create_jwt_token(username: str):
    expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "exp": expires,
        "type": "access"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


if __name__ == "__main__":
    print("Testando sistema de autenticação")

    test_password = "SenhaSegura123!"
    hashed = hash_password(test_password)
    print(f"Senha: {test_password}")
    print(f"Hash gerado: {hashed[:30]}...")

    verified = verify_password(test_password, hashed)
    print(f"Verificação correta: {verified}")

    verified_wrong = verify_password("senhaerrada", hashed)
    print(f"Verificação incorreta: {verified_wrong}")

    token = create_jwt_token("usuario_teste")
    print(f"\nToken JWT: {token[:30]}...")

    payload = verify_jwt_token(token)
    print(f"Payload: {payload}")

    print("\nSistema funcionando ")