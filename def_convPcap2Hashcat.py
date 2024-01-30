from cls_collPcap import collPcap

def convPcap2Hashcat(pcapPath:str, hcPath:str):
    collCls = collPcap()
    collCls.read(pcapPath, hashcatFlag=True)
    
    hcFile = open(hcPath, 'w')
    hcFile.write('WPA*02*')
    hcFile.write(collCls.MIC)
    hcFile.write('*')
    hcFile.write(collCls.MAC_AP)
    hcFile.write('*')
    hcFile.write(collCls.MAC_CLIENT)
    hcFile.write('*')
    hcFile.write(collCls.ESSID)
    hcFile.write('*')
    hcFile.write(collCls.NONCE_AP)
    hcFile.write('*')
    hcFile.write(collCls.NONCE_CLIENT)
    hcFile.write('*02\x0A')
    hcFile.close()