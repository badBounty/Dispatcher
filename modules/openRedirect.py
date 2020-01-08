import requests
import urllib3
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenRedirect():

	payloads = []
	parameters = []
	data = []
	outputActivated = False

	def activateOutput(self):
		self.outputActivated = True

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
		print('Finished! Please check output/openRedirect.csv for results!')


	def output(self):
		df = pd.DataFrame(self.data, columns = ['Url','parameter','payload','destination'])
		df.to_csv('output/openRedirect.csv', index = False)


	def testOpenRedirect(self,session,url):
		for parameter in self.parameters:
			for payload in self.payloads:
				finalPayload = parameter.replace("{payload}",payload)
				
				url_to_scan = url + finalPayload

				response = session.get(url_to_scan, verify = False)
				
				response_list = response.url.split('/')
				#print (response_list)
				if response_list[2] == 'google.com':
					print('Url ' + url_to_scan + ' was redirected')
					print('To ' + response.url)
		
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

		self.output()

