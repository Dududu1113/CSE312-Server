import hashlib
import re
import bcrypt
import uuid

def extract_credentials(request):
    body = request.body.decode("utf-8")
    params = body.split("&")
    credentials = {}

    for param in params:
        key, value = param.split("=")
        key = key.strip()
        value = decodeHelper(value.strip())
        credentials[key] = value

    if "totpCode" in credentials:
        return {
            "username": credentials.get("username", ""),
            "password": credentials.get("password", ""),
            "totpCode": credentials.get("totpCode", "")
        }

    return [credentials.get("username", ""), credentials.get("password", "")]

def decodeHelper(encoded_str):
    decoded_str = ""
    i = 0
    while i < len(encoded_str):
        if encoded_str[i] == "%" and i + 2 < len(encoded_str):
            hex_value = encoded_str[i + 1:i + 3]
            decoded_str += chr(int(hex_value, 16))
            i += 3
        else:
            decoded_str += encoded_str[i]
            i += 1
    return decoded_str

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&()\-_=\[\]]", password):
        return False
    if re.search(r"[^a-zA-Z0-9!@#$%^&()\-_=\[\]]", password):
        return False
    return True

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(hashed_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), hashed_password)

def generate_auth_token():
    return str(uuid.uuid4())

def hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()