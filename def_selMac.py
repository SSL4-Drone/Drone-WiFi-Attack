def selMac(vicFlag=False, bssFlag=False):
    if vicFlag == True:
        vicAddr = input('Input Victim MAC (Empty is broadcast) : ').upper()
        if (vicAddr == ''):
            vicAddr = 'FF:FF:FF:FF:FF:FF'
    else:
        vicAddr = None
    if bssFlag == True:
        bssAddr = input('Input BSSID MAC : ').upper()
    else:
        bssAddr = None
        
    return (vicAddr, bssAddr)