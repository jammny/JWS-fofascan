'''
    JWS-fofascan是JWS系统的fofa收集模块。
                                        by-jammny
'''
import requests, base64, json, hashlib
from pandas import DataFrame
from colorama import init, Fore

class JWSfofa:
    def __init__(self):
        with open("config.json") as f:
            j = json.load(f)
        # FOFA用户配置信息
        self.email = j[0]["email"]
        self.key = j[0]["key"]
        self.size = j[0]["size"]
        self.headers = {
            'User-Agent': 'Mozilla / 5.0 (Windows NT 10.0 ; Win64 ; x64 ; rv: 85.0) Gecko / 20100101Firefox / 85.0',
        }

    def check_info(self):
        try:
            url = "https://fofa.so/api/v1/info/my?email={}&key={}".format(self.email, self.key)
            r = requests.get(url=url, headers=self.headers, timeout=10)
            if r.status_code == 200 and '"isvip":true' in r.text:
                print (Fore.BLUE + ">>>>身份认证成功！你好，{}".format(r.json()["username"]))
                self.select_info()
            else:
                print (Fore.RED + ">>>>身份认证失败！请绑定信息！")
        except requests.exceptions.ConnectionError:
            print (Fore.RED + ">>>>连接失败！")

    def select_info(self):
        try:
            keyworld = input(Fore.BLUE + ">>>>FOFA语法：")
            base64_keyworld = base64.b64encode(keyworld.encode('utf-8')).decode("utf-8")
            url = "https://fofa.so/api/v1/search/all?email={}&key={}&qbase64={}&size={}&fields=host,title,ip,port,server".format(
                self.email, self.key, base64_keyworld, self.size)
            r = requests.get(url=url, headers=self.headers, timeout=10)
            if r.status_code == 200 and "errmsg" not in r.text:
                res = r.json()["results"]
                print(Fore.BLUE + ">>>>Fofa获取有效信息：{}".format(len(res)))
                tables_list = []
                for res_list in res:
                    table_list = []
                    print("-----------------------------------------")
                    print(Fore.GREEN + "域名：{}".format(res_list[0]))
                    print(Fore.GREEN + "标题：{}".format(res_list[1]))
                    print(Fore.GREEN + "IP：{}".format(res_list[2]))
                    print(Fore.GREEN + "端口：{}".format(res_list[3]))
                    print(Fore.GREEN + "服务器：{}".format(res_list[4]))
                    table_list.append(res_list[0])
                    table_list.append(res_list[1])
                    table_list.append(res_list[2])
                    table_list.append(res_list[3])
                    table_list.append(res_list[4])
                    tables_list.append(table_list)
                print("-----------------------------------------")
                self.write_csv(tables_list, keyworld)
            else:
                print (r.json()["errmsg"])
        except requests.exceptions.ConnectionError:
            print ("连接异常！")

    # 文件名 MD5
    def file_name(self, keyworld):
        m = hashlib.md5()
        m.update(keyworld.encode("utf8"))
        psw = m.hexdigest()
        return psw

    # 数据写入csv
    def write_csv(self, tables_list, keyworld):
        name = ['域名', '标题', 'IP', '端口', '服务器']
        c = DataFrame(columns=name, data=tables_list)
        name = self.file_name(keyworld)
        c.to_csv('result/{}.csv'.format(name))
        return name

    # 程序入口：
    def run(self):
        self.check_info()

if __name__ == "__main__":
    init(autoreset=True)
    print(Fore.BLUE + r'''
       ___          _______        __       __                          
      | \ \        / / ____|      / _|     / _|                         
      | |\ \  /\  / / (___ ______| |_ ___ | |_ __ _ ___  ___ __ _ _ __  
  _   | | \ \/  \/ / \___ \______|  _/ _ \|  _/ _` / __|/ __/ _` | '_ \ 
 | |__| |  \  /\  /  ____) |     | || (_) | || (_| \__ \ (_| (_| | | | |
  \____/    \/  \/  |_____/      |_| \___/|_| \__,_|___/\___\__,_|_| |_|
                                                                        
                                                                        ——by jammny.2021.5.10    
    ''')
    fofa = JWSfofa()
    fofa.run()
