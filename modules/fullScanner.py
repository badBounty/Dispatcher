import pandas as pd
import requests

from modules.bucketFinder import BucketFinder
from modules.tokenFinder import TokenFinder
from modules.securityHeaders import HeaderFinder
from modules.openRedirect import OpenRedirect
from modules.cssChecker import CssChecker
from modules.endpointFinder import EndpointFinder

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

		self.session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}
		self.session.headers.update(headers)

	def activateMSTeams(self, msTeams):
		self.bucketFinder.activateMSTeams(msTeams)
		self.openRedirect.activateMSTeams(msTeams)
		self.cssChecker.activateMSTeams(msTeams)
		self.endpointFinder.activateMSTeams(msTeams)

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

		return(final_data_df, final_error_df)

	def run(self, urls):

		self.bucketFinder.activateOutput()

		for url in urls:
			try:
				response = self.session.get(url, verify = False, timeout = 3)
			except requests.exceptions.ConnectionError:
				print('Url: ' + url + ' Timed out')
				self.error_data.append(['full',url,url,'Timeout'])
				continue
			except Exception as e:
				print (e)
				continue

			if response.status_code == 404:
				print('Url: ' + url + ' returned 404')
				self.error_data.append(['full',url,url,'Returned 404'])
				continue
			print('Scanning ' + url + ' with s3bucket module')
			self.bucketFinder.process(url)
			print('Scanning ' + url + ' with token module')
			self.tokenFinder.process(url)
			print('Scanning ' + url + ' with header module')
			self.headerFinder.process(url)
			print('Scanning ' + url + ' with openred module')
			self.openRedirect.process(url)
			print('Scanning ' + url + ' with css module')
			self.cssChecker.process(url)
			print('Scanning ' + url + ' with endpoint module')
			self.endpointFinder.process(url)