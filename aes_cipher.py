import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000)
    raw_key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(raw_key)


def create_fernet_from_password(password:str, salt: bytes) -> Fernet:
    key = derive_key_from_password(password, salt)
    return Fernet(key)


def encrypt_message(message:str, password:str, salt:bytes) -> bytes:
    f = create_fernet_from_password(password, salt)
    message_bytes = message.encode('utf-8')
    encrypted_message = f.encrypt(message_bytes)
    return encrypted_message


def decrypt_message(encrypted_message:bytes, password:str, salt:bytes) -> str:
    f = create_fernet_from_password(password, salt)
    decrypted_bytes = f.decrypt(encrypted_message)
    return decrypted_bytes.decode('utf-8')  


def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)   


