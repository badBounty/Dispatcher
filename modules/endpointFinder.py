import requests
import urllib3
import pandas as pd
import time

from modules.openRedirect import OpenRedirect
from extra.helper import Helper

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EndpointFinder():

	def __init__(self, SESSION):
		self.scanned_targets = []

		self.openRedirect = OpenRedirect(SESSION)
		self.helper = Helper()

		self.data = []
		self.error_data = []

		self.outputActivated = False
		self.msTeamsActivated = False

		self.invalid_codes = [301,302,303,400,403,404,503]

		self.session = SESSION

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

		output = []
		verboseOutput = []

		try:
			normal_response = self.session.get(url, verify = False, timeout = 3, allow_redirects = False)
		except requests.exceptions.Timeout:
			return output, verboseOutput
		except Exception as e:
			print(e)
			return output, verboseOutput

		try:
			#Wont allow redirects
			endpoint_response = self.session.get(url+endpoint, verify = False, timeout = 3, allow_redirects = False)
		except requests.exceptions.Timeout:
			return output, verboseOutput
		except Exception as e:
			print(e)
			return output, verboseOutput

		for code in self.invalid_codes:
			if normal_response.status_code == code:
				return output, verboseOutput

		#Endpoint append returns 404 or 301 (redirect)
		for code in self.invalid_codes:
			if endpoint_response.status_code == code:
				return output, verboseOutput

		response_len = len(normal_response.text)
		end_response_len = len(endpoint_response.text)
		endpoint_len = len(endpoint)
		#Verifying response length
		#Cases where endpoint does not modify anything or only adds the endpoint len will return
		if(response_len - endpoint_len <= end_response_len <= response_len + endpoint_len):
			return output, verboseOutput
		else:
			if endpoint == '/login':
				output_tmp, verboseOutput_tmp = self.openRedirect.process(url+endpoint, url)
				output.append(output_tmp)
				output.append('EndpointFinder found: '+ url + endpoint)
				verboseOutput.append('EndpointFinder found login, started openRedirect')
			else:
				self.data.append(['Endpoint found',url,url,'Endpoint ' + url+endpoint + ' was found, it should be checked'])
				output.append('EndpointFinder found: '+ url + endpoint)
				verboseOutput.append('EndpointFinder found: '+ url + endpoint)
			
			output = [x for x in output if x != []]
			verboseOutput = [x for x in verboseOutput if x != []]
			return output, verboseOutput

	def process(self, url):

		if url in self.scanned_targets:
			return
		self.scanned_targets.append(url)

		output = []
		verboseOutput = []

		#Backspace verify
		if url[-1] == '/':
			url = url[:-1]

		for endpoint in self.endpoints:
			time.sleep(.5)
			output_tmp, verboseOutput_tmp = self.scanEndpoint(url, endpoint)
			output.append(output_tmp)
			verboseOutput.append(verboseOutput_tmp)

		output = self.helper.normalizeList(output)
		verboseOutput = self.helper.normalizeList(verboseOutput)
		return output, verboseOutput

	#Receives an urlList
	def run(self, urls):
		
		for url in urls:
			output = []
			verboseOutput = []

			print('----------------------------------------------------')
			print('Scanning '+ url)

			if not self.helper.verifyURL(self.session, url, url, self.error_data, 'endpointFinder'):
				continue

			output, verboseOutput = self.process(url)

			for item in output:
				print(item)