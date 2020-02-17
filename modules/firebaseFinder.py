import requests
import urllib3
import re
import sys
import subprocess
import time
import os
import pandas as pd

from extra.helper import Helper

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FirebaseFinder():

	def __init__(self):
		self.scanned_targets = []
		self.data = []
		self.error_data = []
		self.msTeamsActivated = False
		self.outputActivated = False
		self.helper = Helper()

		self.session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}
		self.session.headers.update(headers)


	def activateOutput(self):
		self.outputActivated = True

	def showStartScreen(self):
		print('---------------------------------------------------------------------------------------')
		print('---------------------------++++++++++++++----+++++++++++++-------------./*/.-----------')
		print('--------------------./*/.--++++++++++++++----++++++++++++++----------------------------')
		print('---------------------------+++---------------+++--------++++----./*/.------------------')
		print('---./*/.-------------------+++---------------+++--------++++---------------------------')
		print('---------------------------+++++++++---------++++++++++++++----------------------------')
		print('------------./*/.----------+++++++++---------++++++++++++++-------------./*/.----------')
		print('---------------------------+++---------------+++--------++++---------------------------')
		print('---------------------------+++---------------+++--------++++---------------------------')
		print('---------------------------+++---------------++++++++++++++--------------------./*/.---')
		print('------------./*/.----------+++---------------+++++++++++++-------./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('-------------------------- Starting vulnerable firebase finder --------------------------')
		print('Searching firebase databases on input...')

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

	def filterInvalids(self,some_list):
		res = []
		#------ Filter invalid matches
		for item in some_list:
			if all(char not in item for char in ['\\','=','>','<','[',']','{','}',';','(',')','_']):
				res.append(item)
		return res

	def check_firebase(self, url, endpoint, firebases):

		output = []
		for firebase in firebases:
			try:
				firebase_response = self.session.get(firebase, verify = False, timeout = 3)
			except Exception as e:
				print (e)
				continue

			if firebase_response.status_code == 200:
				output.append('FirebaseFinder found open firebase: ' + firebase)
				print('Open firebase found!')
				self.data.append(['Open firebase', url, endpoint, 'There was an open firebase found at ' + firebase])

		return output

	def get_firebases(self, session, url, host):

		if url in self.scanned_targets:
			return []

		self.scanned_targets.append(url)

		response = session.get(url, verify = False, timeout = 3)

		#Firebases come in the form
		#https://*.firebaseio.com

		#---------Way I----------
		firebaseHTTPS = re.findall('"https://([^\"/,]+).firebaseio.com"', response.text)
		firebaseHTTPS = self.filterInvalids(firebaseHTTPS)
		firebaseHTTP = re.findall('"http://([^\"/,]+).firebaseio.com"', response.text)
		firebaseHTTP = self.filterInvalids(firebaseHTTP)


		firebase_list = firebaseHTTPS + firebaseHTTP
		firebase_list = list(dict.fromkeys(firebase_list))

		for i in range (len(firebase_list)):
			firebase_list[i] = 'http://' + firebase_list[i] + '.firebaseio.com/.json'

		return firebase_list

	def process(self, url, endpoint):

		output = []
		firebases = self.get_firebases(self.session, endpoint, url)
		output.append(self.check_firebase(url, url, firebases))

		output = filter(None, output)
		output = [item for sublist in output for item in sublist]
		return output

	#Receives an urlList
	def run(self, urls):
		
		for url in urls:
			output = []
			print('----------------------------------------------------')
			print('Scanning '+ url)

			if not self.helper.verifyURL(self.session, url, url, self.error_data, 'firebaseFinder'):
				continue

			firebases = self.get_firebases(self.session, url, url)
			output.append(self.check_firebase(url, 'html code', firebases))

			js_in_url = self.helper.get_js_in_url(self.session, url)
			
			for js_endpoint in js_in_url:
				if not self.helper.verifyURL(self.session, url, js_endpoint, self.error_data, 'firebaseFinder'):
					continue
				# Searching for buckets
				firebases = self.get_firebases(self.session, js_endpoint, url)
				output.append(self.check_firebase(url, js_endpoint, firebases))

				#Search urls in js file
				http_in_js = self.helper.get_http_in_js(self.session, url)

				for http_endpoint in http_in_js:
					if not self.helper.verifyURL(self.session, url, http_endpoint, self.error_data, 'firebaseFinder'):
						continue
					firebases = self.get_firebases(self.session, http_endpoint, url)
					output.append(self.check_firebase(url, http_endpoint, firebases))

			output = filter(None, output)
			output = [item for sublist in output for item in sublist]
			output = list(dict.fromkeys(output))
			for item in output:
				print(item)