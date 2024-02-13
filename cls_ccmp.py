from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct
from binascii import hexlify
from scapy.all import *

def mac2bytes(mac:str)->bytes:
	return bytes.fromhex(mac.replace(':', ''))



class ccmp:
    # def decrypt(key, data):
    #     ccmp_nonce = b"\x00" + b"\xae\x79\x6a\x48\x75\x2a" + b"\x00\x00\x00\x00\x24\xD2"
    #     print("ccmp n:", ccmp_nonce)
    #     encData = AES.new(key, AES.MODE_CCM, ccmp_nonce, mac_len=8)
    #     #mic = b'\x16\x90\xE7\xE2\xA6\x55\x9C\x54'
    #     #decrypted_data = enc_cipher.decrypt_and_verify(data, mic)
    #     decData = encData.decrypt(data)
    #     return decData

    def encrypt(encKey:bytes, plainData, addr1:str, addr2:str, addr3:str, pn:int):
        ccmpNonce = b"\x00" + mac2bytes(addr2) + struct.pack('>Q', pn)[2:]
            # PN을 6바이트 형식으로 변환 
            
        print('ccmpNonce : ', hexlify(ccmpNonce).decode('ascii'))
        
        aad = b"\x08\x42" +\
            mac2bytes(addr1) +\
            mac2bytes(addr2) +\
            mac2bytes(addr3) +\
            b"\x00\x00"
        print('aad : ', hexlify(aad).decode('ascii'))
            
        cipher = AES.new(encKey, AES.MODE_CCM, ccmpNonce, mac_len=8)
        cipher.update(aad)
        encData = cipher.encrypt_and_digest(raw(plainData))
        print('raw : ', hexlify(raw(plainData)).decode('ascii'))
        print('encData1 : ', hexlify(encData[0]).decode('ascii'))
        
        encData = encData[0]+encData[1]
        print('encData2 : ', hexlify(encData).decode('ascii'))
        return encData
        # encData[0] = Data
        # encData[1] = MIC
