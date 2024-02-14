import os

def selIface(reSelFlag=False):
    filePath = './interface.txt'
    if reSelFlag == True:
        os.remove(filePath)
        # 인터페이스 재선택 시, 기존 캐시 파일을 지움
    
    if (os.path.exists(filePath)):
        file = open(filePath, 'r')
        iface = file.readline()
        # 파일이 존재하면 읽음
    else:
        iface = input("Input your interface : ")
        file = open(filePath, 'w')
        file.write(iface)
        # 파일이 존재하지 않으면 생성
    file.close()
    
    if iface.isalnum() == False:
        print('Not allow special character.')
        os.remove(filePath)
        selIface()
        # 특수문자가 존재하면 재입력 (간단한 CMDI 방지)
    else:
        os.system('sudo ifconfig '+iface+' down')
        os.system('sudo iwconfig '+iface+' mode monitor')
        os.system('sudo ifconfig '+iface+' up')
        # 모니터 모드 전환
    
    return iface