[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.12-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">
[![License](https://img.shields.io/badge/License-MIT-red)](https://github.com/t3l3machus/kcbrute/blob/main/LICENSE)
<img src="https://img.shields.io/badge/Experimental-121212">

## Purpose
Basic brute-force script targeting the standard Keycloak Admin/User Console browser login flow.  
![Screenshot 2025-03-27 142402](https://github.com/user-attachments/assets/dd260042-3c4a-4ec1-a917-a42b7cddc11e)

#### ❗Disclaimer
This script may temporarily and/or permanently lock user accounts if **brute force detection** is enabled on the target Keycloak server. Unauthorized use is illegal. Created For security testing purposes only. You are responsible for your actions.

## Installation
```
git clone https://github.com/t3l3machus/kcbrute && cd kcbrute && pip3 install -r requirements.txt
```


## Usage
1. Copy the full URL of the target keycloak server you wish to attack. It typically looks something like this:
  ```
  https://192.168.1.51:8443/realms/master/protocol/openid-connect/auth?client_id=security-admin-console&redirect_uri=https%3A%2F%2F192.168.1.51%3A8443%2Fadmin%2Fmaster%2Fconsole%2F&state=d47a2004-6749-4651-8955-  ae1bd290ad82&response_mode=query&response_type=code&scope=openid&nonce=42c82af0-fb83-4211-90b6-6404226bb092&code_challenge=xqljsSmaLXaBRzouH6LhEq7PaomvhUDE-bNeHSCRd_U&code_challenge_method=S256
  ```
  **Important**: If you have visited the login URL in the past, delete all cookies and perform a hard refresh (`CTRL + SHIFT + R`) before copying the URL.  

2. Fire up `kcbrute` providing the login URL, username and password lists of your choice:
  ```
  python3 kcbrute.py -v -l 'https://192.168.1.51:8443/realms/master/protocol/openid-connect/auth?client_id=security-admin-console&redirect_uri=https%3A%2F%2F192.168.1.51%3A8443%2Fadmin%2Fmaster%2Fconsole%2F&state=d47a2004-6749-4651-8955-ae1bd290ad82&response_mode=query&response_type=code&scope=openid&nonce=42c82af0-fb83-4211-90b6-6404226bb092&code_challenge=xqljsSmaLXaBRzouH6LhEq7PaomvhUDE-bNeHSCRd_U&code_challenge_method=S256' -u usernames.txt -p passwords.txt
  ```

### Supported options:
```
usage: kcbrute.py [-h] -l LOGIN_URL -u USERNAMES_FILE -p PASSWORDS_FILE [-t THREADS] [-r] [-s] [-q] [-v]

Basic brute-force script targeting the standard Keycloak Admin/User Console browser login flow.

options:
  -h, --help            show this help message and exit

BASIC OPTIONS:
  -l LOGIN_URL, --login-url LOGIN_URL
                        Full Keycloak OpenID Authorization Endpoint URL to attack (Typically something like: https://keycloak.example.com/realms/{REALM}/protocol/openid-
                        connect/auth?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={UUID}&response_mode={MODE}&response_type={TYPE}&scope=openid&nonce={UUID}&code_challenge={TOKEN}&code_challenge_method={TYPE} ).
  -u USERNAMES_FILE, --usernames-file USERNAMES_FILE
                        File containing a usernames list.
  -p PASSWORDS_FILE, --passwords-file PASSWORDS_FILE
                        File containing a passwords list.
  -t THREADS, --threads THREADS
                        Number of threads to use.
  -r, --accept-risk     By selecting this option, you consent to attacking the host.
  -s, --success-stop    Stop upon finding a valid pair.

OUTPUT:
  -q, --quiet           Do not print the banner on startup.
  -v, --verbose         Verbose output.

```

