from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct
from binascii import hexlify
from scapy.all import *

def mac2bytes(mac:str)->bytes:
	return bytes.fromhex(mac.replace(':', ''))


class ccmp:
    def decrypt(decKey:bytes, encData:bytes, addr2:str, pn:bytes):
        ccmpNonce = b"\x00" + mac2bytes(addr2) + pn
        # 0x00 + ADDR2 + PN
        cipher = AES.new(decKey, AES.MODE_CCM, ccmpNonce, mac_len=8)
        decData = cipher.decrypt(encData)
        if b'\xaa\xaa\x03\x00\x00\x00' in decData[:6]:
            # 802.11 LLC Check
            print(hexlify(decData).decode('ascii'))
            return True
        else:
            return False
        

    def encrypt(encKey:bytes, plainData:bytes, addr1:str, addr2:str, addr3:str, pn:int):
        ccmpNonce = b"\x00" + mac2bytes(addr2) + struct.pack('>Q', pn)[2:]
        # 0x00 + ADDR2 + (PN을 6바이트 형식으로 변환)
        # print('ccmpNonce : ', hexlify(ccmpNonce).decode('ascii'))
        
        aad = b"\x08\x42" +\
            mac2bytes(addr1) +\
            mac2bytes(addr2) +\
            mac2bytes(addr3) +\
            b"\x00\x00"
        # Frame Ctl + A1 + A2 + A3 + Seq Ctl (생략, + A4 + QoS Ctl)
        # print('aad : ', hexlify(aad).decode('ascii'))
            
        cipher = AES.new(encKey, AES.MODE_CCM, ccmpNonce, mac_len=8)
        cipher.update(aad)
        encData = cipher.encrypt_and_digest(raw(plainData))
        encData = encData[0]+encData[1]
        # encData[0] = Data
        # encData[1] = MIC

        return encData

