import socket

class IPinterpreter():
    def __init__(self, targets):
        self._targets = targets
        self.__scope_value=''

    #Main fuction who returned proper IPaddress of targets for program
    def IPcalc(self):
        self.__ipchecker()
        self.__scope_value = self._targets.split('.')[-1]

        if '-' in self.__scope_value:
            self._targets = self._targets.split('.')
            self.__scope_value = self.__scope_value.split('-')
            return self.__scopeNetwork()
        elif '/' in self.__scope_value:
            self.__scope_value = self.__scope_value.split('/')
            try:
                self.__scope_value = list(map(int, self.__scope_value))
                self._targets = self._targets.split('.')
            except:
                print('Wrong Input')
                return 0
            return self.__subnetCalc()
        else:
            return self._targets

    def __scopeNetwork(self):
        self._targets.append('.'.join(self._targets[0:3])+'.'+self.__scope_value[0])
        self._targets.append('.'.join(self._targets[0:3])+'.'+self.__scope_value[1])
        self._targets=self._targets[-2:]
        return self._targets

    #Calculate first and last address from the range given by '/' like 192.168.0.0/24 give us list with 192.168.0.1 and 192.168.0.254
    def __subnetCalc(self):
        subnets=[]
        ip_range=['','']
        self._targets[3]=self._targets[3].split('/')[0]
        hosts=0

        for oct in range(1, 5):
            if(self.__scope_value[1] < 8*oct):
                hosts=2**(8-(self.__scope_value[1]-8*(oct-1)))
                subnets.append(0)

                for ip in range(256//hosts):
                    subnets.append((hosts*(ip+1)))

                for inx in range(len(subnets)):
                    if int(self._targets[oct-1]) in range(subnets[inx], subnets[inx+1]):
                        for step in range(0,4):
                            if (oct-1)==step:
                                ip_range[0]+=str(subnets[inx]+1)+'.'
                                ip_range[1]+=str(subnets[inx+1]-1)+'.'
                                break
                            else:
                                ip_range[0]+=self._targets[step]+'.'
                                ip_range[1]+=self._targets[step]+'.'
                        break
                
                for _ in range(4-ip_range[0].count('.')):
                    ip_range[0]+='1.'
                    if(ip_range[1].count('.')==3):
                        ip_range[1]+='254.'
                    else:
                        ip_range[1]+='255.'

                ip_range[0]=ip_range[0][:-1]
                ip_range[1]=ip_range[1][:-1]
                break

        self._targets=ip_range
        return self._targets

    #function checking if IP is given in proper format for app
    def __ipchecker(self):
        test=self._targets
        try:
            test = socket.gethostbyname(test)
        except:
            pass
        if test.count('.')!=3:
            print('Not proper ip address/name site format')
            exit()

        test=test.split('.')
        for text in range(len(test)-1):
            try:
                text=int(text)
                if text not in range(0,256):
                    print('Number out of range')
                    exit()

            except:
                print('Not number')
                exit()

        try:
            test[3]=int(test[3])

        except:
            if ('-' not in test[3]) and ('/' not in test[3]):
                print('Only using - and / to setting range')
                exit()

            if ('-') in test[3]:
                test[3]=test[3].split('-')
                try:
                    test[3][0] = int(test[3][0])
                    test[3][1] = int(test[3][1])

                    if test[3][0] not in range(0, 255) or test[3][1] not in range(0, 255) or test[3][0] > test[3][1]:
                        print('Last oct number out of range or wrong range')
                        exit()

                except:
                    print('Propably not number')
                    exit()

            else:
                test[3]=test[3].split('/')
                try:
                    test[3][0] = int(test[3][0])
                    test[3][1] = int(test[3][1])

                    if test[3][0] not in range(0, 255) or test[3][1] not in range(1, 31):
                        print('Last oct number out of range or wrong subnet number')

                except:
                    print('Propably not number')
                    exit()