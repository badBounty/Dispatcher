import requests
import urllib3
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenRedirect():

	payloads = []
	parameters = []
	data = []

	def output(self):
		df = pd.DataFrame(self.data, columns = ['Url','parameter','payload'])
		df.to_csv('output/openRedirect.csv', index = False)


	def testOpenRedirect(self,url):

		for parameter in self.parameters:
			for payload in self.payloads:
				finalPayload = parameter.replace("{payload}",payload)
				
				url_to_scan = url + finalPayload

				response = requests.get(url_to_scan, verify = False)
				
				if response.history:
					for resp in response.history:
						print (resp.status_code, resp.url)
					print('Url ' + url + ' was redirected')
					print('Payload: ' + finalPayload)
					self.data.append([url,parameter,payload])
					return

				else:
					print('Url ' + url + ' was not redirected')

		
		return


	def run(self, urls):

		with open('extra/openRedirect_parameters.txt') as fp:
			lines = fp.read()
			self.parameters = lines.split('\n')

		with open('extra/openRedirect_payloads.txt') as fp:
			lines = fp.read()
			self.payloads = lines.split('\n')

		#print(self.parameters)
		#print(self.payloads)

		for url in urls:

			self.testOpenRedirect(url)

		self.output()

