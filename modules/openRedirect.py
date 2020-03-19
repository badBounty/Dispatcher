import requests
import urllib3
import pandas as pd
from extra.helper import Helper

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenRedirect():

	def __init__(self, SESSION):
		self.scanned_targets = []

		self.helper = Helper()

		self.data = []
		self.error_data = []

		self.outputActivated = False
		self.msTeamsActivated = False

		self.session = SESSION

		with open('extra/openRedirect_parameters.txt') as fp:
			lines = fp.read()
			self.parameters = lines.split('\n')

		with open('extra/openRedirect_payloads.txt') as fp:
			lines = fp.read()
			self.payloads = lines.split('\n')

	def activateOutput(self):
		self.outputActivated = True

	def activateMSTeams(self, msTeams):
		self.msTeamsActivated = True
		self.msTeams = msTeams

	def showStartScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('----------------------------++++++++++++------++++++++++++-------------./*/.-----------')
		print('--------------------./*/.--++++++++++++++-----++++++++++++++---------------------------')
		print('---------------------------+++--------+++-----+++-------+++++---./*/.------------------')
		print('---./*/.-------------------+++--------+++-----+++------+++++---------------------------')
		print('---------------------------+++--------+++-----++++++++++++-----------------------------')
		print('------------./*/.----------+++--------+++-----+++++++++-----------------./*/.----------')
		print('---------------------------+++--------+++-----+++---++++-------------------------------')
		print('---------------------------+++--------+++-----+++-----++++-----------------------------')
		print('---------------------------++++++++++++++-----+++-------++++-------------------./*/.---')
		print('------------./*/.-----------++++++++++++------+++--------++++----./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('--------------------------- Starting open redirect scanner ----------------------------')
		print('Scanning for open redirect on input...')

	def showEndScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('Finished! Please check output for results!')


	def output(self):
		data_df = pd.DataFrame(self.data, columns = ['Vulnerability','MainUrl','Reference','Description'])
		error_df = pd.DataFrame(self.error_data, columns = ['Module','MainUrl','Reference','Reason'])
		return(data_df, error_df)

	#Testing open redirect
	def testOpenRedirect(self, session, url):

		output = []
		verboseOutput = []

		if url in self.scanned_targets:
			return output, verboseOutput

		self.scanned_targets.append(url)

		if 'login' not in url:
			return output, verboseOutput

		try:
			response = session.get(url, verify = False)
		except Exception as e:
			verboseOutput.append('OpenRedirect finder caught exception ' + e)
			return output, verboseOutput

		#headers = response.headers
		#cookie = headers["Set-Cookie"]
		#header_update = {'Set-Cookie': cookie}
		#self.session.headers.update(header_update)

		#print(self.session.headers)

		#For each endpoint we try parameters and payloads
		for parameter in self.parameters:
			#print('Reached')
			for payload in self.payloads:
				finalPayload = parameter.replace("{payload}",payload)
				
				url_to_scan = url + finalPayload

				try:
					response = self.session.get(url_to_scan, verify = False)
				except Exception as e:
					verboseOutput.append('OpenRedirect finder caught exception ' + e)
					continue

				if response.status_code == 404:
					if self.outputActivated:
						print('Url: ' + url + ' returned 404')
						self.error_data.append(['openred',url,url,'Returned 404'])
					continue
				
				#If on the redirect history we see google.com as host
				#The information is added for output
				for resp in response.history:
					resp_split = resp.url.split('/')
					if resp_split[2] == 'google.com':
						print (resp.status_code, resp.url)
						self.data.append(['Open Redirect Vulnerability',url,url,'An open redirect vulnerability was found with parameter: ' + parameter + ' and payload: ' + payload])
						output.append('OpenRedirectFinder found possible open redirect vulnerability on: ' + url + 'with parameter: ' + parameter + ' and payload: ' + payload)
						if self.msTeamsActivated:
							self.msTeams.title('Open redirect vulnerability found!')
							self.msTeams.text('Found at ' + url + 'with parameter: ' + parameter + ' and payload: ' + payload)
							self.msTeams.send()

		return output, verboseOutput


	def process(self, url, host):

		output = []
		verboseOutput = []
		output, verboseOutput = self.testOpenRedirect(self.session, url)
		
		return output, verboseOutput

	def run(self, urls):

		for url in urls:
			output = []
			print('----------------------------------------------------')
			print('Scanning ' + url)
			if not self.helper.verifyURL(self.session, url, url, self.error_data, 'full'):
				continue

			output, verboseOutput = self.process(url, url)

			for item in output:
				print(item)

