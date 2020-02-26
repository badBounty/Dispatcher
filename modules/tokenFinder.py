import os
import requests
import re
import pandas as pd

from extra.helper import Helper

class TokenFinder():

	def __init__(self):
		self.scanned_targets = []

		self.data = []
		self.error_data = []
		self.outputActivated = False

		self.helper = Helper()

		self.session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		self.session.headers.update(headers)

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

		return http_endpoints

	#Searches certain keywords on site
	def tokenProcess(self, session, host, url):

		output = []

		if url in self.scanned_targets:
			return output

		self.scanned_targets.append(url)

		try:
			response = session.get(url, verify = False)
		except:
			return output

		if response.status_code == 404:
			print('Url: ' + url + ' returned 404')
			self.error_data.append(['token', host, url, 'Returned 404'])
			return output

		#tokens = re.findall('token:"(.+?)"', response.text)
		#tokens_2 = re.findall('Token:"(.+?)"', response.text)
		usernames = re.findall('Username:"(.+?)"', response.text)
		passwords = re.findall('Password:"(.+?)"', response.text)
		access_key_ids = re.findall('access_key_id:"(.+?)"', response.text)
		secret_access_key_ids = re.findall('secret_access_key_id:"(.+?)"', response.text)
		authorization = re.findall('authorization:"(.+?)"', response.text)
		api_key = re.findall('api_key:"(.+?)"', response.text)
		licence_key = re.findall('license_key:"(.+?)"', response.text)

		'''
		if len(tokens) > 0:
			for value in tokens:
				self.data.append(['Information disclosure', host , url , 'The following token was found: ' + value])
				output.append('Token finder found token: ' + value + 'at ' + url)
		if len(tokens_2) > 0:
			for value in tokens_2:
				self.data.append(['Information disclosure', host , url , 'The following token was found: ' + value])
				output.append('Token finder found token: ' + value + 'at ' + url)
		'''
		if len(licence_key) > 0:
			for value in licence_key:
				self.data.append(['Information disclosure', host , url , 'The following licence_key was found: ' + value])
				output.append('Token finder found license_key: ' + value + 'at ' + url)
		if len(api_key) > 0:
			for value in api_key:
				self.data.append(['Information disclosure', host , url , 'The following key was found: ' + value])
				output.append('Token finder found api_key: ' + value + 'at ' + url)
		if len(usernames) > 0:
			for value in usernames:
				self.data.append(['Information disclosure', host , url , 'The following username was found: ' + value])
				output.append('Token finder found username: ' + value + 'at ' + url)
		if len(passwords) > 0:
			for value in passwords:
				self.data.append(['Information disclosure', host , url , 'The following password was found: ' + value])
				output.append('Token finder found password: ' + value + 'at ' + url)
		if len(access_key_ids) > 0:
			for value in access_key_ids:
				self.data.append(['Information disclosure', host , url , 'The following access_key_id was found: ' + value])
				output.append('Token finder found access_key_id: ' + value + 'at ' + url)
		if len(secret_access_key_ids) > 0:
			for value in secret_access_key_ids:
				self.data.append(['Information disclosure', host , url , 'The following secret_access_key_id was found: ' + value])
				output.append('Token finder found secret_access_key_id: ' + value + 'at ' + url)
		if len(authorization) > 0:
			for value in authorization:
				self.data.append(['Information disclosure', host , url , 'The following auth_token was found: ' + value])
				output.append('Token finder found auth token: ' + value + 'at ' + url)

		return output

	def process(self, url, endpoint):

		output = []
		output.append(self.tokenProcess(self.session, url, endpoint))
		output = filter(None, output)
		output = [item for sublist in output for item in sublist]
		return output

	def run(self, urls):

		for url in urls:
			output = []
			print('----------------------------------------------------')
			print('Scanning '+ url)
			if not self.helper.verifyURL(self.session, url, url, self.error_data, 'full'):
				continue

			js_in_url = self.helper.get_js_in_url(self.session, url)
			#print(js_in_url)
			for js_endpoint in js_in_url:
				if not self.helper.verifyURL(self.session, url, js_endpoint, self.error_data, 'full'):
					continue
				output.append(self.tokenProcess(self.session, url, js_endpoint))

				http_in_js = self.helper.get_http_in_js(self.session, js_endpoint)
				#print(http_in_js)
				for http_endpoint in http_in_js:
					if not self.helper.verifyURL(self.session, url, http_endpoint, self.error_data, 'full'):
						continue
					output.append(self.tokenProcess(self.session, js_endpoint, http_endpoint))

			output = filter(None, output)
			output = [item for sublist in output for item in sublist]
			output = list(dict.fromkeys(output))
			for item in output:
				print(item)



