import requests
import os
import pandas as pd
import urllib3
import sys
import re

from extra.helper import Helper

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CssChecker():

	def __init__(self, SESSION):
		self.scanned_targets = []

		self.data = []
		self.error_data = []
		self.outputActivated = False
		self.msTeamsActivated = False

		self.helper = Helper()

		self.session = SESSION


	def activateOutput(self):
		self.outputActivated = True

	def activateMSTeams(self, msTeams):
		self.msTeamsActivated = True
		self.msTeams = msTeams

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
		print('Finished! Please check output for results!')

	def output(self):
		data_df = pd.DataFrame(self.data, columns = ['Vulnerability','MainUrl','Reference','Description'])
		error_df = pd.DataFrame(self.error_data, columns = ['Module','MainUrl','Reference','Reason'])
		return(data_df, error_df)

	def filterInvalids(self,some_list):
		res = []
		#------ Filter invalid matches
		for item in some_list:
			if all(char not in item for char in ['\\','=','>','<','[',']','{','}',';','(',')']):
				res.append(item)
		return res

	#Checks if css file found returns code 200
	def scan_css(self, session, host, url):

		if url in self.scanned_targets:
			return

		self.scanned_targets.append(url)

		output = []
		verboseOutput = []

		#We split url and host to check, if vuln is found, if host domain != url domain
		url_split = url.split('/')
		host_split = host.split('/')

		if url[-1] == '\\' or url[-1] == '/':
			url = url[:-1]

		try:
			response = session.get(url, verify = False)
		except requests.exceptions.MissingSchema:
			if self.outputActivated:
				print('Missing schema error on ' + url)
			return output
		except:
			if url_split[2] != host_split[2]:
				self.data.append(['Possible css injection', ' ' + host, ' ' + url, 'Could not access the css file'])
				output.append('Possible css injection on: ' + url)
				verboseOutput.append('Possible css injection on: ' + url + 'could not access css file')
				if self.msTeamsActivated:
					self.msTeams.title('Possible css injection')
					self.msTeams.text('The css file '+ url +' could not be accessed. Host url: ' + host)
					output('The css file '+ url +' could not be accessed. Host url: ' + host)
					self.msTeams.send()
			else:
				verboseOutput.append('Css file ' + url + ' was accessed normally')
			return output, verboseOutput

		if response.status_code != 200:
			if url_split[2] != host_split[2]:
				self.data.append(['Possible css injection', host, url, ' Css file did not return 200'])
				output.append('CssChecker found possible injection: ' + url)
				verboseOutput.append('CssChecker found possible injection: ' + url + ' css file did not return 200')
				if self.msTeamsActivated:
					self.msTeams.title('Possible css injection')
					self.msTeams.text('The css file '+ url +' did not return code 200. Host url: ' + host)
					self.msTeams.send()
			else:
				verboseOutput.append('Css file ' + url + ' was accessed normally')	
		else:
			verboseOutput.append('Css file ' + url + ' was accessed normally')

		return output, verboseOutput

	def process(self, url, css):

		output = []
		verboseOutput = []
		output, verboseOutput = self.scan_css(self.session, url, css)
		return output, verboseOutput

	def run(self, urls):

		for url in urls:
			output = []
			verboseOutput = []
			print('----------------------------------------------------')
			print('Scanning ' + url)

			if not self.helper.verifyURL(self.session, url, url, self.error_data, 'cssChecker'):
				continue

			css_found = self.helper.get_css_in_url(self.session, url)
			#print(css_found)

			for css in css_found:
				output_tmp, verboseOutput_tmp = self.scan_css(self.session, url, css)
				output.append(output_tmp)
				verboseOutput.append(verboseOutput_tmp)

			output = self.helper.normalizeList(output)
			verboseOutput = self.helper.normalizeList(verboseOutput)
			for item in output:
				print(item)