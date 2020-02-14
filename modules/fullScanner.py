import pandas as pd
import requests

from modules.bucketFinder import BucketFinder
from modules.tokenFinder import TokenFinder
from modules.securityHeaders import HeaderFinder
from modules.openRedirect import OpenRedirect
from modules.cssChecker import CssChecker
from modules.endpointFinder import EndpointFinder
from modules.firebaseFinder import FirebaseFinder
from extra.helper import Helper

class FullScanner():

	def __init__(self, outputFolderName):
		self.data = []
		self.error_data = []

		self.bucketFinder = BucketFinder()
		self.tokenFinder = TokenFinder()
		self.headerFinder = HeaderFinder(outputFolderName)
		self.openRedirect = OpenRedirect()
		self.cssChecker = CssChecker()
		self.endpointFinder = EndpointFinder()
		self.firebaseFinder = FirebaseFinder()

		self.helper = Helper()

		self.session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}
		self.session.headers.update(headers)

	def activateMSTeams(self, msTeams):
		self.bucketFinder.activateMSTeams(msTeams)
		self.openRedirect.activateMSTeams(msTeams)
		self.cssChecker.activateMSTeams(msTeams)
		self.endpointFinder.activateMSTeams(msTeams)
		self.firebaseFinder.activateMSTeams(msTeams)
	def showStartScreen(self):
		print('---------------------------------------------------------------------------------------')
		print('---------------------------++++++++++++++-------++++++++++++-----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++------++++++++++++++--------------------------')
		print('---------------------------+++-----------------+++--------------./*/.------------------')
		print('---./*/.-------------------+++-----------------+++-------------------------------------')
		print('---------------------------+++++++++++---------+++++++++++++---------------------------')
		print('------------./*/.----------+++++++++++---------++++++++++++++-----------./*/.----------')
		print('---------------------------+++----------------------------+++--------------------------')
		print('---------------------------+++----------------------------+++--------------------------')
		print('---------------------------+++-----------------++++++++++++++------------------./*/.---')
		print('------------./*/.----------+++------------------+++++++++++++----./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('---------------------- Starting full scan, this may take a while ----------------------')
		print('Searching urls...')

	def showEndScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('Finished! Please check output for results!')


	def output(self):

		#HeaderFinder output
		self.headerFinder.output()
		
		final_data_df = pd.DataFrame(self.data, columns = ['Vulnerability','MainUrl','Reference','Description'])
		final_error_df = pd.DataFrame(self.error_data, columns = ['Module','MainUrl','Reference','Reason'])
		
		#Adding bucket output
		data_df, error_df = self.bucketFinder.output()
		final_data_df = final_data_df.append(data_df)
		final_error_df = final_error_df.append(error_df)

		#Adding token output
		data_df, error_df = self.tokenFinder.output()
		final_data_df = final_data_df.append(data_df)
		final_error_df = final_error_df.append(error_df)
		
		#Adding openred output
		data_df, error_df = self.openRedirect.output()
		final_data_df = final_data_df.append(data_df)
		final_error_df = final_error_df.append(error_df)
		
		#Adding css checker output
		data_df, error_df = self.cssChecker.output()
		final_data_df = final_data_df.append(data_df)
		final_error_df = final_error_df.append(error_df)

		#Adding endpoint finder output
		data_df, error_df = self.endpointFinder.output()
		final_data_df = final_data_df.append(data_df)
		final_error_df = final_error_df.append(error_df)

		#Adding firebase finder output
		data_df, error_df = self.firebaseFinder.output()
		final_data_df = final_data_df.append(data_df)
		final_error_df = final_error_df.append(error_df)

		return(final_data_df, final_error_df)

	def run(self, urls):

		self.bucketFinder.activateOutput()

		#Start by iterating over urls
		for url in urls:
			print('Scanning '+ url)
			if not self.helper.verifyURL(self.session, url, url, self.error_data, 'full'):
				continue

			self.bucketFinder.process(url, url)
			self.firebaseFinder.process(url, url)
			self.tokenFinder.process(url, url)
			self.headerFinder.process(url)
			self.openRedirect.process(url, url)
			self.endpointFinder.process(url)

			#We get js files from the url
			js_in_url = self.helper.get_js_in_url(self.session, url)
			#We get css from the url
			css_in_url = self.helper.get_css_in_url(self.session, url)

			print('Scanning js files found in '+ url)
			#We run the tools that interact with js files
			for js_endpoint in js_in_url:
				if not self.helper.verifyURL(self.session, url, js_endpoint, self.error_data, 'full'):
					continue
				self.bucketFinder.process(url, js_endpoint)
				self.firebaseFinder.process(url, js_endpoint)
				self.tokenFinder.process(url, js_endpoint)

				#Search urls in js file
				urls_in_js = self.helper.get_http_in_js(self.session, url)
				#We run the tool that interacts with sub_urls
				print('Scanning sub_urls found in '+ js_endpoint + ' from ' + url)
				for sub_url in urls_in_js:
					if not self.helper.verifyURL(self.session, url, js_endpoint, self.error_data, 'full'):
						continue
					self.bucketFinder.process(url, sub_url)
					self.firebaseFinder.process(url, sub_url)
					self.tokenFinder.process(url, sub_url)

			for css_endpoint in css_in_url:
				self.cssChecker.process(url, css_endpoint)



