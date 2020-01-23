import os
import requests
import re
import pandas as pd

class TokenFinder():

	scanned_targets = []
	data = []
	error_data = []
	outputActivated = False
	# Regex used
	regex_str = r"""
  		(?:"|')                               # Start newline delimiter
  		(
    		((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    		[^"'/]{1,}\.                        # Match a domainname (any character + dot)
    		[a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    		|
    		((?:/|\.\./|\./)                    # Start with /,../,./
    		[^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
    		[^"'><,;|()]{1,})                   # Rest of the characters can't be
    		|
    		([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    		[a-zA-Z0-9_\-/]{1,}                 # Resource name
    		\.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
    		|
    		([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
    		[a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
    		|
    		([a-zA-Z0-9_\-]{1,}                 # filename
    		\.(?:php|asp|aspx|jsp|json|
    		     action|html|js|txt|xml)        # . + extension
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
  		)
  		(?:"|')                               # End newline delimiter
		"""

	def activateOutput(self):
		self.outputActivated = True

	def showStartScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('---------------------------++++++++++++++------++++++++++++++----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++------++++++++++++++--------------------------')
		print('--------------------------------++++-----------+++--------------./*/.------------------')
		print('---./*/.------------------------++++-----------+++-------------------------------------')
		print('--------------------------------++++-----------+++++++++++-----------------------------')
		print('------------./*/.---------------++++-----------+++++++++++--------------./*/.----------')
		print('--------------------------------++++-----------+++-------------------------------------')
		print('--------------------------------++++-----------+++-------------------------------------')
		print('--------------------------------++++-----------+++-----------------------------./*/.---')
		print('------------./*/.---------------++++-----------+++---------------./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('-------------------------------- Starting token finder --------------------------------')
		print('Searching sensitive info on input...')

	def showEndScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('Finished! Please check output for results!')

	def output(self):
		data_df = pd.DataFrame(self.data, columns = ['Vulnerability','MainUrl','Reference','Description'])
		error_df = pd.DataFrame(self.error_data, columns = ['Module','MainUrl','Reference','Reason'])
		return(data_df, error_df)


	def filterInvalids(self,some_list):
		res = []
		#------ Filter invalid matches
		for item in some_list:
			if all(char not in item for char in ['\\','=','>','<','[',']','{','}',';','(',')']):
				res.append(item)
		return res

	def get_js_files(self, session, url):
		regex = re.compile(self.regex_str, re.VERBOSE)

		try:
			response = session.get(url, verify = False)
		except Exception:
			return []

		all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
		js_endpoints = list()
		for match in all_matches:
			if '.js' in list(match)[0]:
				js_endpoints.append(list(match)[0])

		return js_endpoints

	def get_http_in_js(self, session, url):
		regex = re.compile(self.regex_str, re.VERBOSE)

		http_endpoints = list()
		try:
			response = session.get(url)
		except Exception:
			return http_endpoints
		matches_in_js = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
		for match in matches_in_js:
			if 'http' in list(match)[0]:
				http_endpoints.append(list(match)[0])

		return http_endpoints

	#Searches certain keywords on site
	def process(self, session, host, url):

		try:
			response = session.get(url, verify = False)
		except:
			return []

		if response.status_code == 404:
			print('Url: ' + url + ' returned 404')
			self.error_data.append(['token', host, url, 'Returned 404'])
			return []

		tokens = re.findall('token:"(.+?)"', response.text)
		tokens_2 = re.findall('Token:"(.+?)"', response.text)
		usernames = re.findall('Username:"(.+?)"', response.text)
		passwords = re.findall('Password:"(.+?)"', response.text)
		access_key_ids = re.findall('access_key_id:"(.+?)"', response.text)
		secret_access_key_ids = re.findall('secret_access_key_id:"(.+?)"', response.text)
		authorization = re.findall('authorization:"(.+?)"', response.text)
		api_key = re.findall('api_key:"(.+?)"', response.text)

		if len(tokens) > 0:
			for token in tokens:
				self.data.append(['Information disclosure', host , url , 'The following token was fonund: ' + token])
		if len(tokens_2) > 0:
			for token in tokens_2:
				self.data.append(['Information disclosure', host , url , 'The following token was fonund: ' + token])
		if len(api_key) > 0:
			for key in api_key:
				self.data.append(['Information disclosure', host , url , 'The following key was fonund: ' + key])
		if len(usernames) > 0:
			for username in usernames:
				self.data.append(['Information disclosure', host , url , 'The following username was fonund: ' + username])
		if len(passwords) > 0:
			for password in passwords:
				self.data.append(['Information disclosure', host , url , 'The following password was fonund: ' + password])
		if len(access_key_ids) > 0:
			for key in access_key_ids:
				self.data.append(['Information disclosure', host , url , 'The following access_key_id was fonund: ' + key])
		if len(secret_access_key_ids) > 0:
			for key in secret_access_key_ids:
				self.data.append(['Information disclosure', host , url , 'The following secret_access_key_id was fonund: ' + key])
		if len(authorization) > 0:
			for key in authorization:
				self.data.append(['Information disclosure', host , url , 'The following auth_token was fonund: ' + key])

	def run(self, urls):

		session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		session.headers.update(headers)

		for url in urls:
			if self.outputActivated:
				print('Scanning '+ url)

			self.process(session, url, url)
			js_in_url = self.get_js_files(session, url)

			for js_endpoint in js_in_url:
				self.process(session, url, js_endpoint)

				http_in_js = self.get_http_in_js(session, js_endpoint)
				#print(http_in_js)
				for http_endpoint in http_in_js:
					self.process(session, js_endpoint, http_endpoint)


		self.output()


