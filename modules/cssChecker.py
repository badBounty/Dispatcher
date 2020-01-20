import requests
import os
import pandas as pd
import urllib3
import sys
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CssChecker():

	data = []
	outputActivated = False

	def activateOutput(self):
		self.outputActivated = True


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
		print('Finished! Please check output/cssChecker.csv for results!')

	def output(self):
		df = pd.DataFrame(self.data, columns = ['SourceURL','Css_Url','Reason'])
		df.to_csv('output/'+self.inputName+'cssChecker.csv', index = False)

	def filterInvalids(self,some_list):
		res = []
		#------ Filter invalid matches
		for item in some_list:
			if all(char not in item for char in ['\\','=','>','<','[',']','{','}',';','(',')']):
				res.append(item)
		return res

	def get_css_files(self, session, url):

		try:
			get_response = session.get(url, verify = False)
		except Exception:
			return []
			
		get_text = get_response.text

		css_found = re.findall('([^\s",\'%]+)\.css', get_text)
		#print(css_found)
		css_found = self.filterInvalids(css_found)
		for i in range (len(css_found)):
			#We add the .css that was removed at the regex
			css_found[i] = css_found[i] + '.css'

		host = get_response.url.split('/')
		host_protocol = host[0]
		host_name = host[2]
		only_hostname = host_protocol + '//' + host_name

		for i in range (len(css_found)):
			if css_found[i][:2] == '//':
				css_found[i] = 'https:' + css_found[i]
			elif css_found[i][:1] == '/':
				css_found[i] = only_hostname + css_found[i]
			elif css_found[i][:1] != 'h':
				css_found[i] = 'https://' + css_found[i]

		return(css_found)

	#Checks if css file found returns code 200
	def scan_css(self, session, host, url):

		try:
			response = session.get(url, verify = False)
		except:
			self.data.append([host, url, 'Could not access'])
			return

		if response.status_code != 200:
			self.data.append([host, url, 'Returned ' + response.status_code])

	def run(self, urls, inputName):

		self.inputName = inputName

		session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		session.headers.update(headers)

		for url in urls:
			if self.outputActivated:
				print('Scanning ' + url)

			css_found = self.get_css_files(session, url)

			for css in css_found:
				self.scan_css(session, url, css)

		self.output()

