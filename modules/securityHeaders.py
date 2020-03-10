import requests
import os
import pandas as pd
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HeaderFinder():

	def __init__(self, inputName):
		self.scanned_targets = []
		self.inputName = inputName
		self.data = []
		self.outputActivated = False

		self.session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		self.session.headers.update(headers)

	def activateOutput(self):
		self.outputActivated = True

	def showStartScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('----------------------------++++++++++++------++++-------++++----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++-----++++-------++++--------------------------')
		print('---------------------------+++----------------++++-------++++---./*/.------------------')
		print('---./*/.-------------------+++----------------++++-------++++--------------------------')
		print('---------------------------+++++++++++++------+++++++++++++++--------------------------')
		print('------------./*/.----------++++++++++++++-----+++++++++++++++-----------./*/.----------')
		print('--------------------------------------+++-----++++-------++++--------------------------')
		print('--------------------------------------+++-----++++-------++++--------------------------')
		print('---------------------------++++++++++++++-----++++-------++++------------------./*/.---')
		print('------------./*/.-----------+++++++++++++-----++++-------++++----./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('-------------------------- Starting security header scanner ---------------------------')
		print('Listing headers on input...')

	def showEndScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('Finished! Please check output for results!')

	def output(self, path):
		df = pd.DataFrame(self.data, columns = ['url','Content-Security-Policy','X-XSS-Protection',
								   		'x-frame-options', 'X-Content-Type-options', 'Strict-Transport-Security',
								   		'Access-Control-Allow-Origin'])

		df.to_csv(path, index = False)

	def scan_target(self, session, url):

		try:
			if self.outputActivated:
				print('Scanning ' + url)
			response = session.get(url, verify = False)
		except requests.exceptions.MissingSchema:
			print('Missing schema error on ' + url)
			return
		except requests.exceptions.Timeout:
			print('Timeout error on ' + url)
			return
		except requests.exceptions.ConnectionError:
			print('Connection error on ' + url)
			return
		except Exception as e:
			return

		content_security_policy = 0
		x_xss_protection = 0
		x_frame_options = 0
		x_content_type_options = 0
		strict_transport_security = 0
		access_control_allow_policy = 0
		if response.status_code != 404:
			if 'Content-Security-Policy' in response.headers:
				content_security_policy = 1
			if 'X-XSS-Protection' in response.headers:
				x_xss_protection = 1
			if 'x-frame-options' in response.headers:
				x_frame_options = 1
			if 'X-Content-Type-options' in response.headers:
				x_content_type_options = 1	
			if 'Strict-Transport-Security' in response.headers:
				strict_transport_security = 1
			if 'Access-Control-Allow-Origin' in response.headers:
				access_control_allow_policy = 1

		self.data.append([url, content_security_policy, 
		    		x_xss_protection, x_frame_options, x_content_type_options, 
		    		strict_transport_security, access_control_allow_policy])


	def process(self, url):

		if url in self.scanned_targets:
			return

		self.scanned_targets.append(url)

		self.scan_target(self.session, url)

	#Verifies headers on each url and adds data to output
	def run(self, urls):

		for url in urls:

			self.process(url)