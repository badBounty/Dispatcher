import requests
import os
import pandas as pd
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HeaderFinder():

	data = []

	def run(self, urls):

		print('---------------------------------------------------------------------------------------')
		print('---------------------------++++++++++++++-----+++---------+++----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++-----+++---------+++--------------------------')
		print('---------------------------+++----------------+++---------+++---./*/.------------------')
		print('---./*/.-------------------+++----------------+++---------+++--------------------------')
		print('---------------------------++++++++++++++-----+++++++++++++++--------------------------')
		print('------------./*/.----------++++++++++++++-----+++++++++++++++-----------./*/.----------')
		print('--------------------------------------+++-----+++---------+++--------------------------')
		print('--------------------------------------+++-----+++---------+++--------------------------')
		print('---------------------------++++++++++++++-----+++---------+++------------------./*/.---')
		print('------------./*/.----------++++++++++++++-----+++---------+++----./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('------------------------------------ Handerllon © -------------------------------------')
		print('                                                                                       ')
		print('-------------------------- Starting security header scanner ---------------------------')
		print('Listing headers on input...')

		for url in urls:
			try:
				print('Scanning ' + url)
				response = requests.get(url, verify = False)
			except requests.exceptions.MissingSchema:
				print('Missing schema error on ' + url)
				continue
			except requests.exceptions.Timeout:
				print('Timeout error on ' + url)
				continue
			except requests.exceptions.ConnectionError:
				print('Connection error on ' + url)
				continue

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


		df = pd.DataFrame(self.data, columns = ['url','Content-Security-Policy','X-XSS-Protection',
								   		'x-frame-options', 'X-Content-Type-options', 'Strict-Transport-Security',
								   		'Access-Control-Allow-Origin'])

		df.to_csv('output/headerFinder.csv', index = False)