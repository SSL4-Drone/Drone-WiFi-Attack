import hmac
import binascii
import hashlib

def PRF512(PMK:bytes, A:str, B:bytes)->bytes:
    ptk1 = hmac.new(PMK, binascii.a2b_qp(A) + B + chr(0).encode(), hashlib.sha1).digest()
    ptk2 = hmac.new(PMK, binascii.a2b_qp(A) + B + chr(1).encode(), hashlib.sha1).digest()
    ptk3 = hmac.new(PMK, binascii.a2b_qp(A) + B + chr(2).encode(), hashlib.sha1).digest()
    ptk4 = hmac.new(PMK, binascii.a2b_qp(A) + B + chr(3).encode(), hashlib.sha1).digest()
    ptk = ptk1 + ptk2 + ptk3 + ptk4
    return ptk
    # MIC는 제거하고 반환
    
def getPTK(PMK:bytes, AP_MAC:bytes, STN_MAC:bytes, ANonce:bytes, SNonce:bytes)->bytes:
    B = min(AP_MAC, STN_MAC) + max(AP_MAC, STN_MAC) \
            + min(ANonce, SNonce) + max(ANonce, SNonce)
    return PRF512(PMK, 'Pairwise key expansion\x00', B)
