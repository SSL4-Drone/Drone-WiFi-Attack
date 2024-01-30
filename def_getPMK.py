import hashlib

def getPMK(ssid:str, password:str)->bytes:
    return hashlib.pbkdf2_hmac('sha1', password.encode('ascii'), ssid.encode('ascii'), 4096, 32)