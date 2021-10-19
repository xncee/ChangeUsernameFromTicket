import os, uuid, datetime, time, base64, string, random
guid = str(uuid.uuid1())
device_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
try:
        import requests
except ImportError:
        os.system("pip install requests")
        import requests
try:
        import autopy
except ImportError:
        os.system("pip install autopy")
        import autopy
try:
        from Crypto.Cipher import AES, PKCS1_v1_5
        from Crypto.PublicKey import RSA
        from Crypto.Random import get_random_bytes
except ModuleNotFoundError:
        os.system("pip install pycryptodome")
        from Crypto.Cipher import AES, PKCS1_v1_5
        from Crypto.PublicKey import RSA
        from Crypto.Random import get_random_bytes
class Ticket():
        def __init__(self):
                self.url = "https://instagram.com/api/v1/bloks/apps/com.instagram.challenge.navigation.take_challenge/"
                self.login()
                self.head = {
                        "Host": 'i.instagram.com',
                        "Cookie": f'csrftoken={self.coo.get("csrftoken")}; mid={self.coo.get("mid")}',
                        "User-Agent": 'Instagram 187.0.0.32.120 Android (25/7.1.2; 192dpi; 720x1280; google; G011A; G011A; intel; en_US; 289692181)',
                        "Accept-Language": 'en-US',
                        "Content-Type": 'application/x-www-form-urlencoded; charset=UTF-8',
                        "Connection": 'close'
                }
                self.get_info()
                self.get_steps()
                self.send_choice()
                self.send_code()
                self.confirm()
                self.change_password()
                self.edit_profile()
        def password_encrypt(self, password):
                publickeyid, publickey = self.password_publickeys()
                session_key = get_random_bytes(32)
                iv = get_random_bytes(12)
                timestamp = str(int(time.time()))
                decoded_publickey = base64.b64decode(publickey.encode())
                recipient_key = RSA.import_key(decoded_publickey)
                cipher_rsa = PKCS1_v1_5.new(recipient_key)
                rsa_encrypted = cipher_rsa.encrypt(session_key)
                cipher_aes = AES.new(session_key, AES.MODE_GCM, iv)
                cipher_aes.update(timestamp.encode())
                aes_encrypted, tag = cipher_aes.encrypt_and_digest(password.encode("utf8"))
                size_buffer = len(rsa_encrypted).to_bytes(2, byteorder='little')
                payload = base64.b64encode(b''.join([b"\x01",publickeyid.to_bytes(1, byteorder='big'),iv,size_buffer,rsa_encrypted,tag,aes_encrypted]))
                return f"#PWD_INSTAGRAM:4:{timestamp}:{payload.decode()}"
        def password_publickeys(self):
                resp = requests.get('https://i.instagram.com/api/v1/qe/sync/')
                publickeyid = int(resp.headers.get('ig-set-password-encryption-key-id'))
                publickey = resp.headers.get('ig-set-password-encryption-pub-key')
                return publickeyid, publickey
        def login(self):
                self.username = input("[+] Username: ")
                password = input("[+] Password: ")
                head = {"User-Agent": f'Instagram 135.0.0.00.000 (iPhone12,12; iPhone OS 12; en_US; en) AppleWebKit/600'}
                data = {
                        'guid': guid,
                        'password': password,
                        'username': self.username,
                        'device_id': f"android-{device_id}",
                        'login_attempt_count': '0'
                }
                req = requests.post("https://i.instagram.com/api/v1/accounts/login/", headers=head, data=data)
                if "logged_in_user" in req.text:
                        print(f'[+] Logged In "{self.username}"')
                        self.coo = req.cookies
                elif "Incorrect Username" in req.text:
                        print("[-] The username you entered doesn't belong to an account. Please check your username and try again.")
                        input()
                        exit()
                elif 'Incorrect password' in req.text:
                        print("[-] Sorry, your password was incorrect. Please double-check your password.")
                        input()
                        exit()
                elif 'checkpoint_challenge_required' in req.text:
                        print("[-] checkpoint_required")
                        self.coo = req.cookies
                        info = requests.get(f"https://i.instagram.com/api/v1{req.json()['challenge']['api_path']}", headers=head, cookies=self.coo)
                        if "step_data" not in info.text:
                                print(f"[-] {info.text}")
                                input()
                                exit()
                        if "phone_number" in info.json()["step_data"] and "email" in info.json()["step_data"]:
                                print(f'[0] Phone_Number: {info.json()["step_data"]["phone_number"]} [1] Email: {info.json()["step_data"]["email"]}')
                        elif "phone_number" in info.json()["step_data"]:
                                print(f'[0] Phone_Number: {info.json()["step_data"]["phone_number"]}')
                        elif "email" in info.json()["step_data"]:
                                print(f'[1] Email: {info.json()["step_data"]["email"]}')
                        else:
                                print("[-] Unknown verification method")
                                input()
                                exit()
                        choice = input('[+] Choice: ')
                        secure_data = {
                                'choice': str(choice),
                                'guid': guid,
                                'device_id': f"android-{device_id}",
                                '_csrftoken': 'massing'}
                        send_choice = requests.post(f"https://i.instagram.com/api/v1{req.json()['challenge']['api_path']}", headers=head, data=secure_data, cookies=self.coo)
                        if "step_data" not in send_choice.text:
                                print(f"[-] {send_choice.text}")
                                input()
                                exit()
                        print(f'[+] Code Sent To: "{send_choice.json()["step_data"]["contact_point"]}"')
                        code = input("[+] Code: ")
                        code_data = {
                                'security_code': str(code),
                                'guid': guid,
                                'device_id': f"android-{device_id}",
                                '_csrftoken': 'massing'}
                        send_code = requests.post(f"https://i.instagram.com/api/v1{req.json()['challenge']['api_path']}", headers=head, data=code_data, cookies=self.coo)
                        if "logged_in_user" in send_code.text:
                                print(f'[+] Logged In "{self.username}"')
                                self.coo = req.cookies
                        else:
                                print(f'[-] {send_code.text}')
                                input()
                                exit()
                else:
                        print(f'[-] {req.text}')
                        input()
                        exit()
        def get_info(self):
                url = "https://i.instagram.com/api/v1/accounts/assisted_account_recovery/"
                data = {
                        "source":"login_help",
                        "_csrftoken": f'{self.coo.get("csrftoken")}',
                        "guid": guid,
                        "device_id": f"android-{device_id}",
                        "query": self.username
                }

                self.info = requests.post(url, headers=self.head, data=data)
                try:
                        self.coo = self.info.cookies
                        self.user_id = self.info.json()['uid']
                        self.challenge_context = self.info.json()['challenge_context']
                        self.cni = self.info.json()['cni']
                        self.nonce_code = self.info.json()['nonce']
                except:
                        print(f"[-] {self.info.text}")
                        input()
                        exit()
        def get_steps(self):
                data = {
                        "_csrftoken": f'{self.coo.get("csrftoken")}',
                        "user_id": f"{self.user_id}",
                        "cni": f"{self.cni}",
                        "nonce_code": f"{self.nonce_code}",
                        "bk_client_context": '{"bloks_version":"e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931","styles_id":"instagram"}',
                        "nest_data_manifest": 'true',
                        "challenge_context": f"{self.challenge_context}",
                        "bloks_versioning_id": 'e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931',
                        "get_challenge": 'true'
                }
                steps = requests.post(self.url, headers=self.head, data=data)
                #print(steps.text)
                if "Help Us Recover Your Account" in steps.text:
                        if r'"Email\"' in steps.text:
                                self.email = steps.text.split(r'"Email\"')[1].split(r'\")\", \"-\"), (bk.action.array.Make, \"')[1].split(r'\", \"16sp\"))))),')[0].replace(r"\\u2022","•")
                                print(f"[0] {self.email}")
                        if 'Phone Number' in steps.text:
                                self.phone = steps.text.split(r'"Phone Number\"')[1].split(r'\")\", \"-\"), (bk.action.array.Make, \"')[1].split(r'\", \"16sp\"))))),')[0].replace(r"\\u2022","•")
                                print(f"[1] {self.phone}")
                else:
                        print(f"[-] Error, 'get_steps', '{steps.status_code}'")
                        input()
                        exit()
        def send_choice(self):
                choice = input("[+] Choice: ")
                data = {
                        "choice": str(choice),
                        "_csrftoken": f'{self.coo.get("csrftoken")}',
                        "is_bloks_web": 'False',
                        "bk_client_context": '{"bloks_version":"e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931","styles_id":"instagram"}',
                        "nest_data_manifest": 'true',
                        "challenge_context": f"{self.challenge_context}",
                        "bloks_versioning_id": 'e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931'
                }
                req = requests.post(self.url, headers=self.head, data=data)
                if "It may take up to a minute for you to receive this code" in req.text:
                        print("[+] Code Sent")
                elif "Select a valid choice" in req.text:
                        if choice=='0' or choice=='1':
                              print("[-] '2' For Email, '3' For Phone_Number.")
                        else:
                              print("[-] '0' For Email, '1' For Phone_Number.")
                        input()
                        exit()
                else:
                        print(f"[-] Error, 'send_choice', '{req.status_code}'")
                        input()
                        exit()
        def send_code(self):
                self.code = input("[+] Code: ")
                data = {
                        "security_code": str(self.code),
                        "_csrftoken": f'{self.coo.get("csrftoken")}',
                        "is_bloks_web": 'False',
                        "bk_client_context": '{"bloks_version":"e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931","styles_id":"instagram"}',
                        "nest_data_manifest": 'true',
                        "challenge_context": f"{self.challenge_context}",
                        "bloks_versioning_id": 'e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931'
                }
                req = requests.post(self.url, headers=self.head, data=data)
                if "Confirm Your Email" in req.text:
                        print("[+] Code Is True")
                elif "Please check the code we sent you and try again" in req.text:
                          print("[-] Please check the code we sent you and try again.")
                          input()
                          exit()
                else:
                        print(f"[-] Error, 'send_code', '{req.status_code}'")
                        input()
                        exit()
                try:
                        self.contact1 = req.text.split(r', (bk.action.bool.Const, false), \"1\", \"\", \"')[1].split(r'\")))))),')[0]
                        #print(self.contact1)
                except Exception as err:
                        #print(f"[-] {err}")
                        print("[-] Error, 'contact1'")
                        input()
                        exit()
                if self.contact1=="":
                        self.confirm_mode = input("[+] Confirm New Email (Y/N): ")
                        if self.confirm_mode.lower()=='y':
                                self.contact1 = input("[+] New Email: ")
                else:
                        self.confirm_mode = input(f"[+] Confirm '{self.contact1}' (Y/N): ")

        def confirm_contact(self, contact_point):
                data = {
                        "_csrftoken": f'{self.coo.get("csrftoken")}',
                        "is_bloks_web": 'False',
                        "skip": '0',
                        "type": self.type,
                        "contact_point": f'{contact_point}',
                        "bk_client_context": '{"bloks_version":"e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931","styles_id":"instagram"}',
                        "nest_data_manifest": 'true',
                        "challenge_context": f"{self.challenge_context}",
                        "bloks_versioning_id": 'e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931'
                }
                self.confirm_req = requests.post(self.url, headers=self.head, data=data)
                #print(self.confirm_req.text)
                if any(success in self.confirm_req.text for success in self.success_confirm):
                        print(f"[+] {contact_point} Confirmed")
                elif "It may take up to a minute for you to receive this code" in self.confirm_req.text:
                        print(f"[+] Code Sent To {contact_point}")
                        self.code = input("[+] Code: ")
                        data = {
                                "security_code": str(self.code),
                                "_csrftoken": f'{self.coo.get("csrftoken")}',
                                "is_bloks_web": 'False',
                                "bk_client_context": '{"bloks_version":"e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931","styles_id":"instagram"}',
                                "nest_data_manifest": 'true',
                                "challenge_context": f"{self.challenge_context}",
                                "bloks_versioning_id": 'e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931'
                        }
                        req = requests.post(self.url, headers=self.head, data=data)
                        if any(success in req.text for success in self.success_confirm):
                                print("[+] Code Is True")
                                print(f"[+] {contact_point} Confirmed")
                        elif "Please check the code we sent you and try again" in req.text:
                                print("[-] Please check the code we sent you and try again.")
                                input()
                                exit()
                        else:
                                print(f"[-] Error, 'send_code', '{req.status_code}'")
                                input()
                                exit()
        def skip_contact(self, contact_point):
                data = {
                        "_csrftoken": f'{self.coo.get("csrftoken")}',
                        "is_bloks_web": 'False',
                        "skip": '1',
                        "contact_point": '',
                        "bk_client_context": '{"bloks_version":"e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931","styles_id":"instagram"}',
                        "nest_data_manifest": 'true',
                        "challenge_context": f"{self.challenge_context}",
                        "bloks_versioning_id": 'e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931'
                }
                self.skip_req = requests.post(self.url, headers=self.head, data=data)
                if any(success in self.skip_req.text for success in self.success_confirm):
                        print(f"[+] {contact_point} Skipped")
                else:
                        #print(self.skip_req.text)
                        print(f"[-] Error, 'skip_contact', '{self.skip_req.status_code}'")
                        input()
                        exit()

        def confirm(self):
                self.success_confirm = ["Add New Phone Number", "Confirm Your Phone Number", "Change Your Password"]
                if self.confirm_mode.lower()=='y':
                        self.type = "email"
                        self.confirm_contact(self.contact1)
                        self.skip_contact("Phone Number")
                elif self.confirm_mode.lower()=='n':
                        self.skip_contact("Email")
                        self.contact2 = self.skip_req.text.split(r', (bk.action.bool.Const, false), \"1\", \"\", \"')[1].split(r'\")))))),')[0]
                        self.type = "phone_number"
                        if self.contact2=="":
                                self.contact2 = input("[+] New PhoneNumber (ex: +962•••••••••): ")
                                self.confirm_contact(self.contact2)
                        else:
                                self.confirm_contact(self.contact2)
                else:
                        print(f"[-] '{self.confirm_mode}' is not one of the available choices.")
                        input()
                        exit()
        def change_password(self):
                new_password = input("[+] New Password: ")
                data = {
                        "_csrftoken": f'{self.coo.get("csrftoken")}',
                        "is_bloks_web": 'False',
                        "bk_client_context": '{"bloks_version":"e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931","styles_id":"instagram"}',
                        "nest_data_manifest": 'true',
                        "challenge_context": f"{self.challenge_context}",
                        "bloks_versioning_id": 'e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931',
                        "enc_new_password1": self.password_encrypt(new_password),
                        "enc_new_password2": self.password_encrypt(new_password)
                }
                req = requests.post(self.url, headers=self.head, data=data, cookies=self.coo)
                if "review_profile" in req.text:
                        print("[+] Password Changed")
                elif "Create a password at least 6 characters long" in req.text:
                        print("[-] Create a password at least 6 characters long.")
                        input()
                        exit()
                else:
                        print(f"[-] Error, 'change_password', '{req.status_code}'")
                        input()
                        exit()
        def edit_profile(self):
                new_username = input("[+] New Username: ")
                autopy.alert.alert(f"{new_username}, Are You Ready? ", "xnce")
                data = {
                        "external_url": '',
                        "_csrftoken": f'{self.coo.get("csrftoken")}',
                        'username': new_username,
                        "is_bloks_web": 'False',
                        "first_name": '',
                        "biography": '',
                        "bk_client_context": '{"bloks_version":"e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931","styles_id":"instagram"}',
                        "nest_data_manifest": 'true',
                        "challenge_context": f"{self.challenge_context}",
                        "bloks_versioning_id": 'e097ac2261d546784637b3df264aa3275cb6281d706d91484f43c207d6661931'
                }
                req = requests.post(self.url, headers=self.head, data=data)
                #print(req.text)
                if req.status_code==200 or new_username in req.text:
                        print("[+] Username Changed Successfully! ")
                        input()
                        exit()
                else:
                        #print(req.text)
                        print(f"[-] Error, 'change_username', '{req.status_code}'")
                        input()
                        exit()
Ticket()
