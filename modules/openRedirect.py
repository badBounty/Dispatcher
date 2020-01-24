import requests
import urllib3
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenRedirect():

	scanned_targets = []

	payloads = []
	parameters = []
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
	def testOpenRedirect(self,session,url):

		if url in self.scanned_targets:
			return

		self.scanned_targets.append(url)

		if 'login' not in url or 'register' not in url:
			return

		#For each endpoint we try parameters and payloads
		for parameter in self.parameters:
			for payload in self.payloads:
				finalPayload = parameter.replace("{payload}",payload)
				
				url_to_scan = url + finalPayload

				try:
					response = session.get(url_to_scan, verify = False)
				except:
					continue
				
				#If on the redirect history we see google.com as host
				#The information is added for output
				for resp in response.history:
					resp_split = resp.url.split('/')
					if resp_split[2] == 'google.com':
						print (resp.status_code, resp.url)
						data.append(['Open Redirect Vulnerability',url,url,'An open redirect vulnerability was found with parameter: ' + parameter + ' and payload: ' + payload])
						if self.msTeamsActivated:
							self.msTeams.title('Open redirect vulnerability found!')
							self.msTeams.text('Found at ' + url + 'with parameter: ' + parameter + ' and payload: ' + payload)
							self.msTeams.send()
		return

	def run(self, urls):

		session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		session.headers.update(headers)

		with open('extra/openRedirect_parameters.txt') as fp:
			lines = fp.read()
			self.parameters = lines.split('\n')

		with open('extra/openRedirect_payloads.txt') as fp:
			lines = fp.read()
			self.payloads = lines.split('\n')

		#print(self.parameters)
		#print(self.payloads)

		for url in urls:
			if self.outputActivated:
				print('Scanning ' + url)

			self.testOpenRedirect(session, url)

