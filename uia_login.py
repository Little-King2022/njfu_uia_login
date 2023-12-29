'''
一个使用 Python 和 Node.js 实现的
NJFU Unified Identity Authentication Login

UIA分为应用服务器app_url和统一鉴权服务器uia_url, 可以按需更改app_url
aes.js用于password加密, 运行在http://127.0.0.1:3000/encrypt, 端口号可以自行更改

@Little-King.
'''

import requests
import time as t
from bs4 import BeautifulSoup
import json

# 阻止https的ssl证书校验报错，方便抓包调试
# 如不需要抓包，可以删除disable_warnings()和verify=False
import urllib3
urllib3.disable_warnings()

app_url = 'http://jwxt.njfu.edu.cn/sso.jsp'
uia_url = f'https://uia.njfu.edu.cn/authserver/login?service={app_url}'
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36'
}

def uia_login(stu_id, stu_pwd):
    session = requests.Session()
    # 1.请求app server以获取cookie
    session.get(app_url, headers=headers, verify=False)
    # 2.请求uia server以获取salt lt dllt
    res = session.get(uia_url, verify=False).text
    soup = BeautifulSoup(res, 'html.parser')
    lt = soup.find('input', {'name': 'lt'})['value']
    salt = soup.find('input', {'id': 'pwdDefaultEncryptSalt'})['value']
    dllt = soup.find('input', {'name': 'dllt'})['value']

    # 3.加密stu_pwd，需要运行node aes.js，端口号可以自行更改
    encode_data = {
        '_p0': stu_pwd,
        '_p1': salt
    }
    stu_pwd = requests.post('http://127.0.0.1:3000/encrypt', data=json.dumps(encode_data)).json()['_p2']
    data = {
        'username' : stu_id,
        'password' : stu_pwd,
        'lt' : lt,
        'dllt' : dllt,
        'execution' : 'e1s1',
        '_eventId' : 'submit',
        'rmShown' : '1'
    }

    # 4.验证该stu_id是否需要另外输入captcha
    captcha_res = requests.get(f'https://uia.njfu.edu.cn/authserver/needCaptcha.html?username={stu_id}&pwdEncrypt2=pwdEncryptSalt&_={int(t.time() * 1000)}', verify=False)
    if captcha_res.text == 'false':
        # 5.向uia server发起鉴权请求。
        res = session.post(uia_url, data=data, verify=False, allow_redirects=True)
        if res.status_code == 200:
            # 此处可以做进一步校验是否完成登录
            print('登录成功')
            return session
        else:
            print('登录失败')
    else:
        print('密码连续错误，暂时被锁定')


# demo
if __name__ == '__main__':
    stu_id = "xxx"
    stu_pwd = "xxx"
    session = uia_login(stu_id, stu_pwd)
    # 登录成功后，就可以使用session完成一些app_server内的请求