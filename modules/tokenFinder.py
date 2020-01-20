import os
import requests
import re
import pandas as pd

class TokenFinder():

	scanned_targets = []
	data = []
	error_data = []
	outputActivated = False

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
		df = pd.DataFrame(self.data, columns = ['SourceURL','Type','Found'])
		df.to_csv('output/'+self.inputName+'/tokenFinder.csv', index = False)
		df2 = pd.DataFrame(self.error_data, columns = ['SourceURL','Reason'])
		df2.to_csv('output/'+self.inputName+'/tokenFinderError.csv', index = False)


	def filterInvalids(self,some_list):
		res = []
		#------ Filter invalid matches
		for item in some_list:
			if all(char not in item for char in ['\\','=','>','<','[',']','{','}',';','(',')']):
				res.append(item)
		return res

	def get_js_files(self, session, url):

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

		regex = re.compile(regex_str, re.VERBOSE)

		try:
			response = session.get(url, verify = False)
		except Exception:
			return []

		all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
		js_endpoints = list()
		for match in all_matches:
			if '.js' in list(match)[0]:
				js_endpoints.append(list(match)[0])

		print(js_endpoints)
		return js_endpoints

	#Searches certain keywords on site
	def process(self, session, url):

		try:
			response = session.get(url, verify = False)
		except:
			#print('Url: ' + url + ' could not be accessed')
			#self.error_data.append([url,'Invalid js file'])
			return []

		if response.status_code == 404:
			print('Url: ' + url + ' returned 404')
			self.error_data.append([url,'Returned 404'])
			return []

		tokens = re.findall('token:"(.+?)"', response.text)
		tokens_2 = re.findall('Token:"(.+?)"', response.text)
		keys = re.findall('key:"(.+?)"', response.text)
		usernames = re.findall('Username:"(.+?)"', response.text)
		passwords = re.findall('Password:"(.+?)"', response.text)
		access_key_ids = re.findall('access_key_id:"(.+?)"', response.text)
		secret_access_key_ids = re.findall('secret_access_key_id:"(.+?)"', response.text)

		if len(tokens) > 0:
			for token in tokens:
				self.data.append([url, 'Token', token])
		if len(tokens_2) > 0:
			for token in tokens_2:
				self.data.append([url, 'Token',token])
		if len(keys) > 0:
			for key in keys:
				self.data.append([url, 'Key', key])
		if len(usernames) > 0:
			for username in usernames:
				self.data.append([url, 'Username', username])
		if len(passwords) > 0:
			for password in passwords:
				self.data.append([url, 'Password', password])
		if len(access_key_ids) > 0:
			for key in access_key_ids:
				self.data.append([url, 'access_key_id', key])
		if len(secret_access_key_ids) > 0:
			for key in secret_access_key_ids:
				self.data.append([url, 'secret_access_key', key])

	def run(self,urls, inputName):

		self.inputName = inputName
		session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		session.headers.update(headers)

		for url in urls:
			if self.outputActivated:
				print('Scanning '+ url)

			self.process(session, url)
			js_in_url = self.get_js_files(session, url)

			#print('Scanning js files...')

			for js_endpoint in js_in_url:
				self.process(session, js_endpoint)

		self.output()


