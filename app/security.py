import os
import base64
import hashlib
import secrets
import json
from typing import Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

MASTER_KEY = "tcc_master_key_32_bytes_12345678901"


if not MASTER_KEY:
    raise ValueError("MASTER_KEY não definida nas variáveis de ambiente")
    
    
key_bytes = MASTER_KEY.encode('utf-8')
if len(key_bytes) < 32:
    MASTER_KEY = MASTER_KEY.ljust(32, '0')
elif len(key_bytes) > 32:
    MASTER_KEY = MASTER_KEY[:32]

def generate_salt(size: int = 16) -> bytes:
    return secrets.token_bytes(size)

def derivateAES_key(salt: bytes, master_key: str = MASTER_KEY) -> bytes:
    key_derivate = hashlib.pbkdf2_hmac(
        'sha256',
        master_key.encode('utf-8'),
        salt,
        100000,
        32
    )
    return key_derivate

def cript_aes(plainText: str, salt: bytes = None) -> Dict:
    try:
        if salt is None:
            salt = generate_salt()
        
        key = derivateAES_key(salt)
        iv = secrets.token_bytes(16)
        
        cripter = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cripter.encryptor()
        
        padder = padding.PKCS7(128).padder()
        text_padded = padder.update(plainText.encode('utf-8')) + padder.finalize()
        
        crypted_text = encryptor.update(text_padded) + encryptor.finalize()
        
        return {
            'cifrado': base64.b64encode(crypted_text).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
        
    except Exception as e:
        raise Exception(f"Erro ao cifrar: {str(e)}")

def decript_aes(cripted_data: Dict) -> str:
    try:
        crypted_text = base64.b64decode(cripted_data['cifrado'])
        salt = base64.b64decode(cripted_data['salt'])
        iv = base64.b64decode(cripted_data['iv'])
        
        chave = derivateAES_key(salt)
        
        cifrador = Cipher(
            algorithms.AES(chave),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cifrador.decryptor()
        
        texto_padded = decryptor.update(crypted_text) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        texto_plano = unpadder.update(texto_padded) + unpadder.finalize()
        
        return texto_plano.decode('utf-8')
        
    except InvalidTag:
        raise Exception("Falha na decifragem")
    except Exception as e:
        raise Exception(f"Erro ao decifrar: {str(e)}")

def generate_signature(data: str, secretkey: str = None) -> str:
    if secretkey is None:
        secretkey = MASTER_KEY
    
    h = hashlib.new('sha256')
    h.update(secretkey.encode('utf-8'))
    h.update(data.encode('utf-8'))
    
    return base64.b64encode(h.digest()).decode('utf-8')

def verify_signature(data: str, signature: str, secretkey: str = None) -> bool:
    signature_created = generate_signature(data, secretkey)
    return secrets.compare_digest(signature_created, signature)

def hash_data(data: str, salt: bytes = None) -> Dict:
    if salt is None:
        salt = generate_salt(16)
    
    hash_result = hashlib.pbkdf2_hmac(
        'sha256',
        data.encode('utf-8'),
        salt,
        100000,
        32
    )
    
    return {
        'hash': base64.b64encode(hash_result).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')
    }

def verify_hash(data: str, stored_hash: str, salt_base64: str) -> bool:
    salt = base64.b64decode(salt_base64)
    new_hash = hash_data(data, salt)
    return secrets.compare_digest(new_hash['hash'], stored_hash)

if __name__ == "__main__":
    print("Testando security.py")
    print(f"Chave: {MASTER_KEY} ({len(MASTER_KEY.encode('utf-8'))} bytes)")
    
    text = "Teste de criptografia"
    crypt = cript_aes(text)
    decrypt = decript_aes(crypt)
    
    print(f"Texto: {text}")
    print(f"Cifrado (início): {crypt['cifrado'][:30]}...")
    print(f"Decifrado: {decrypt}")
    print(f"Teste passou: {text == decrypt}")