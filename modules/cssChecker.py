import requests
import os
import pandas as pd
import urllib3
import sys
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CssChecker():

	data = []
	error_data = []
	outputActivated = False
	msTeamsActivated = False

	def activateOutput(self):
		self.outputActivated = True

	def activateMSTeams(self, msTeams):
		self.msTeamsActivated = True
		self.msTeams = msTeams

	def showStartScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('----------------------------+++++++++++++------+++++++++++++-----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++-----++++++++++++++---------------------------')
		print('---------------------------+++++--------------+++++-------------./*/.------------------')
		print('---./*/.-------------------++++---------------++++-------------------------------------')
		print('---------------------------++++---------------++++-------------------------------------')
		print('------------./*/.----------++++---------------++++----------------------./*/.----------')
		print('---------------------------++++---------------++++-------------------------------------')
		print('---------------------------+++++--------------+++++------------------------------------')
		print('---------------------------++++++++++++++-----++++++++++++++-------------------./*/.---')
		print('------------./*/.-----------+++++++++++++------+++++++++++++-----./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('-------------------------------- Starting css checker ---------------------------------')
		print('Listing headers on input...')

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

	def get_css_files(self, session, url):

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
		css_endpoints = list()
		for match in all_matches:
			if '.css' in list(match)[0]:
				css_endpoints.append(list(match)[0])

		return css_endpoints

	#Checks if css file found returns code 200
	def scan_css(self, session, host, url):

		try:
			response = session.get(url, verify = False)
		except:
			self.data.append(['Possible css injection', host, url, 'Could not access the css file'])
			if msTeamsActivated:
				self.msTeams.title('Possible css injection')
				self.msTeams.text('The css file '+ url +' could not be accessed. Host url: ' + host)
				self.msTeams.send()
			return

		if response.status_code != 200:
			self.data.append(['Possible css injection', host, url, 'Css file did not return 200'])
			if msTeamsActivated:
				self.msTeams.title('Possible css injection')
				self.msTeams.text('The css file '+ url +' did not return code 200. Host url: ' + host)
				self.msTeams.send()

	def run(self, urls):

		session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		session.headers.update(headers)

		for url in urls:
			if self.outputActivated:
				print('Scanning ' + url)

			css_found = self.get_css_files(session, url)

			for css in css_found:
				self.scan_css(session, url, css)
