import requests
import urllib3
import pandas as pd
import time

from modules.openRedirect import OpenRedirect

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EndpointFinder():

	def __init__(self):
		self.scanned_targets = []

		self.openRedirect = OpenRedirect()

		self.data = []
		self.error_data = []

		self.outputActivated = False
		self.msTeamsActivated = False

		self.invalid_codes = [404,301,302,403,503]

		self.session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		self.session.headers.update(headers)

		with open('extra/endpointFinder_endpoints.txt') as fp:
			lines = fp.read()
			self.endpoints = lines.split('\n')

		#print(self.endpoints)

	def activateOutput(self):
		self.outputActivated = True

	def showStartScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('---------------------------++++++++++++++------++++++++++++++----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++------++++++++++++++--------------------------')
		print('---------------------------++++----------------++++-------------./*/.------------------')
		print('---./*/.-------------------++++----------------++++------------------------------------')
		print('---------------------------++++++++++++++------+++++++++++-----------------------------')
		print('------------./*/.----------++++++++++++++------+++++++++++--------------./*/.----------')
		print('---------------------------++++----------------++++------------------------------------')
		print('---------------------------++++----------------++++------------------------------------')
		print('---------------------------++++++++++++++------++++----------------------------./*/.---')
		print('------------./*/.----------++++++++++++++------++++--------------./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('-------------------------------- Starting endpoint finder --------------------------------')
		print('Searching endpoints...')

	def showEndScreen(self):
		print('---------------------------------------------------------------------------------------')
		print('Finished! Please check output for results!')

	def output(self):
		data_df = pd.DataFrame(self.data, columns = ['Vulnerability','MainUrl','Reference','Description'])
		error_df = pd.DataFrame(self.error_data, columns = ['Module','MainUrl','Reference','Reason'])
		return(data_df, error_df)

	def activateMSTeams(self, msTeams):
		self.msTeamsActivated = True
		self.msTeams = msTeams


	def scanEndpoint(self, url, endpoint):

		try:
			normal_response = self.session.get(url, verify = False, timeout = 3)#, allow_redirects = False)
		except requests.exceptions.Timeout:
			return
		except Exception as e:
			print(e)
			return

		try:
			#Wont allow redirects
			endpoint_response = self.session.get(url+endpoint, verify = False, timeout = 3, allow_redirects = False)
		except requests.exceptions.Timeout:
			return
		except Exception as e:
			print(e)
			return

		#print(endpoint_response.status_code)
		#for code in self.invalid_codes:
		#	if normal_response.status_code == code:
		#		return

		#Endpoint append returns 404 or 301 (redirect)
		for code in self.invalid_codes:
			if endpoint_response.status_code == code:
				return

		response_len = len(normal_response.text)
		end_response_len = len(endpoint_response.text)
		endpoint_len = len(endpoint)
		#Verifying response length
		#Cases where endpoint does not modify anything or only adds the endpoint len will return
		if(response_len - endpoint_len <= end_response_len <= response_len + endpoint_len):
			return
		else:
			print('Endpoint ' + endpoint + ' was found on ' + url)
			#print(endpoint_response.status_code)
			self.data.append(['Endpoint found',url,url,'Endpoint ' + url+endpoint + ' was found, it should be checked'])
			#if endpoint == '/login':
			#	print('Login found!, testing open redirect')
			#	self.openRedirect.process(url+endpoint)
			return



	def process(self, url):

		if url in self.scanned_targets:
			return
		self.scanned_targets.append(url)

		#Backspace verify
		if url[-1] == '/':
			url = url[:-1]

		for endpoint in self.endpoints:
			time.sleep(.5)
			#print('Testing endpoint: '+endpoint)
			self.scanEndpoint(url, endpoint)

	#Receives an urlList
	def run(self, urls):
		
		for url in urls:
			print('Scanning '+ url)

			#404 check before process
			try:
				response = self.session.get(url, verify = False)
			except Exception as e:
				print(e)
				continue

			if response.status_code == 404:
				print('Url: ' + url + ' returned 404')
				self.error_data.append(['endpoint',url,url,'Returned 404'])
				continue

			self.process(url)