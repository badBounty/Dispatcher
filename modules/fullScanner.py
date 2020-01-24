import pandas as pd

from modules.bucketFinder import BucketFinder
from modules.tokenFinder import TokenFinder
from modules.securityHeaders import HeaderFinder
from modules.openRedirect import OpenRedirect
from modules.cssChecker import CssChecker

class FullScanner():

	data = []
	error_data = []

	bucketFinder = BucketFinder()
	tokenFinder = TokenFinder()
	headerFinder = HeaderFinder()
	openRedirect = OpenRedirect()
	cssChecker = CssChecker()

	def activateMSTeams(self, msTeams):
		self.bucketFinder.activateMSTeams(msTeams)
		self.openRedirect.activateMSTeams(msTeams)
		self.cssChecker.activateMSTeams(msTeams)

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


	def output(self, outputFolderName):

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

		return(final_data_df, final_error_df)

	def run(self, urls, outputFolderName):

		self.bucketFinder.activateOutput()

		self.bucketFinder.run(urls)
		self.tokenFinder.run(urls)
		self.headerFinder.run(urls, outputFolderName)
		self.openRedirect.run(urls)
		self.cssChecker.run(urls)