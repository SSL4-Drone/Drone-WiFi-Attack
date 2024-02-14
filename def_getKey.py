import hmac
import binascii
import hashlib
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap


def PRF512(PMK:bytes, A:str, B:bytes)->bytes:
    ptk1 = hmac.new(PMK, binascii.a2b_qp(A) + B + chr(0).encode(), hashlib.sha1).digest()
    ptk2 = hmac.new(PMK, binascii.a2b_qp(A) + B + chr(1).encode(), hashlib.sha1).digest()
    ptk3 = hmac.new(PMK, binascii.a2b_qp(A) + B + chr(2).encode(), hashlib.sha1).digest()
    ptk4 = hmac.new(PMK, binascii.a2b_qp(A) + B + chr(3).encode(), hashlib.sha1).digest()
    ptk = ptk1 + ptk2 + ptk3 + ptk4
    return ptk

def getPMK(ssid:str, password:str)->bytes:
    return hashlib.pbkdf2_hmac('sha1', password.encode('ascii'), ssid.encode('ascii'), 4096, 32)

def getPTK(PMK:bytes, AP_MAC:bytes, STN_MAC:bytes, ANonce:bytes, SNonce:bytes)->bytes:
    B = min(AP_MAC, STN_MAC) + max(AP_MAC, STN_MAC) \
            + min(ANonce, SNonce) + max(ANonce, SNonce)
    return PRF512(PMK, 'Pairwise key expansion\x00', B)

def getGTK(kek:bytes, encData:bytes):
    decData = aes_key_unwrap(kek, encData)
    idx = 0
    while (idx <= len(decData)-1):
        if decData[idx] != 221:
            # Vendor Specific 태그를 찾을 때까지 반복
            print(decData[idx])
            idx += int(decData[idx+1])+2
        else:
            # 해당 태그를 찾으면 GTK 슬라이싱 후 반복 종료
            return decData[idx+8:idx+24]