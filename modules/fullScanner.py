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

	def __init__(self, outputFolderName, scope, SESSION):
		self.data = []
		self.error_data = []
		self.textList = []

		self.scope = scope

		self.bucketFinder = BucketFinder(SESSION)
		self.tokenFinder = TokenFinder(SESSION)
		self.headerFinder = HeaderFinder(outputFolderName, SESSION)
		self.openRedirect = OpenRedirect(SESSION)
		self.cssChecker = CssChecker(SESSION)
		self.endpointFinder = EndpointFinder(SESSION)
		self.firebaseFinder = FirebaseFinder(SESSION)

		self.helper = Helper()

		self.session = SESSION


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


	def output(self, path):

		#HeaderFinder output
		self.headerFinder.output(path)
		
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

		final_data_df.drop_duplicates(keep = 'first', inplace = True)
		final_error_df.drop_duplicates(keep = 'first', inplace = True)

		return(final_data_df, final_error_df, self.textList)

	def appendTxtInformation(self, url, bucketFinder, firebaseFinder, openRedirect, endpointFinder, tokenFinder, cssFinder):

		self.textList.append(url)
		self.textList.append('    BucketFinder:')
		if not bucketFinder:
			#print('No finds with bucketFinder')
			self.textList.append('        No finds with bucketFinder')
		else:
			for item in bucketFinder:
				self.textList.append('        ' + item)

		self.textList.append('    FirebaseFinder:')
		if not firebaseFinder:
			#print('No finds with firebaseFinder')
			self.textList.append('        No finds with firebaseFinder')
		else:
			for item in firebaseFinder:
				self.textList.append('        ' + item)

		self.textList.append('    OpenRedirect:')
		if not openRedirect:
			#print('No finds with openRedirect')
			self.textList.append('        No finds with openRedirectFinder')
		else:
			for item in openRedirect:
				self.textList.append('        ' + item)

		self.textList.append('    EndpointFinder:')
		if not endpointFinder:
			#print('No finds with endpointFinder')
			self.textList.append('        No finds with endpointFinder')
		else:
			for item in endpointFinder:
				self.textList.append('        ' + item)

		self.textList.append('    CssFinder:')
		if not cssFinder:
			#print('No finds with cssFinder')
			self.textList.append('        No finds with cssFinder')
		else:
			for item in cssFinder:
				self.textList.append('        ' + item)

		self.textList.append('    TokenFinder:')
		if not tokenFinder:
			#print('No finds with tokenFinder')
			self.textList.append('        No finds with tokenFinder')
		else:
			for item in tokenFinder:
				self.textList.append('        ' + item)

	def run(self, urls):

		self.bucketFinder.activateOutput()

		#Start by iterating over urls
		for url in urls:

			output = []
			verboseOutput = []

			bucketFinderOutput = []
			bucketFinderVerboseOutput = []

			firebaseFinderOutput = []
			firebaseFinderVerboseOutput = []

			openRedirectOutput = []
			openRedirectVerboseOutput = []

			endpointFinderOutput = []
			endpointFinderVerboseOutput = []

			tokenFinderOutput = []
			tokenFinderVerboseOutput = []

			cssFinderOutput = []
			cssFinderVerboseOutput = []

			print('----------------------------------------------------')
			print('Scanning '+ url)
			if not self.helper.verifyURL(self.session, url, url, self.error_data, 'full'):
				continue

			bucketFinderOutput_tmp, bucketFinderVerboseOutput_tmp = self.bucketFinder.process(url,url)
			bucketFinderOutput.append(bucketFinderOutput_tmp)
			bucketFinderVerboseOutput.append(bucketFinderVerboseOutput_tmp)

			firebaseFinderOutput_tmp, firebaseFinderVerboseOutput_tmp = self.firebaseFinder.process(url, url)
			firebaseFinderOutput.append(firebaseFinderOutput_tmp)
			firebaseFinderVerboseOutput.append(firebaseFinderVerboseOutput_tmp)

			output.append(self.headerFinder.process(url))

			openRedirectOutput_tmp, openRedirectVerboseOutput_tmp = self.openRedirect.process(url, url)
			openRedirectOutput.append(openRedirectOutput_tmp)
			openRedirectVerboseOutput.append(openRedirectVerboseOutput_tmp)

			endpointFinderOutput_tmp, endpointFinderVerboseOutput_tmp = self.endpointFinder.process(url)
			endpointFinderOutput.append(endpointFinderOutput_tmp)
			endpointFinderVerboseOutput.append(endpointFinderVerboseOutput_tmp)

			tokenFinderOutput_tmp, tokenFinderVerboseOutput_tmp = self.tokenFinder.process(url, url)
			tokenFinderOutput.append(tokenFinderOutput_tmp)
			tokenFinderVerboseOutput.append(tokenFinderVerboseOutput_tmp)


			#We get js files from the url
			js_in_url = self.helper.get_js_in_url(self.session, url)
			js_in_url = self.helper.checkScope(js_in_url, self.scope)
			#We get css from the url
			css_in_url = self.helper.get_css_in_url(self.session, url)
			css_in_url = self.helper.checkScope(css_in_url, self.scope)

			urls_in_url = self.helper.get_http_in_js(self.session, url)
			urls_in_url = self.helper.checkScope(urls_in_url, self.scope)

			for url_in_url in urls_in_url:
				if not self.helper.verifyURL(self.session, url, url_in_url, self.error_data, 'full'):
					continue

				bucketFinderOutput_tmp, bucketFinderVerboseOutput_tmp = self.bucketFinder.process(url,url_in_url)
				bucketFinderOutput.append(bucketFinderOutput_tmp)
				bucketFinderVerboseOutput.append(bucketFinderVerboseOutput_tmp)

				firebaseFinderOutput_tmp, firebaseFinderVerboseOutput_tmp = self.firebaseFinder.process(url, url_in_url)
				firebaseFinderOutput.append(firebaseFinderOutput_tmp)
				firebaseFinderVerboseOutput.append(firebaseFinderVerboseOutput_tmp)

				tokenFinderOutput_tmp, tokenFinderVerboseOutput_tmp = self.tokenFinder.process(url, url_in_url)
				tokenFinderOutput.append(tokenFinderOutput_tmp)
				tokenFinderVerboseOutput.append(tokenFinderVerboseOutput_tmp)	

			#We run the tools that interact with js files
			for js_endpoint in js_in_url:
				if not self.helper.verifyURL(self.session, url, js_endpoint, self.error_data, 'full'):
					continue

				bucketFinderOutput_tmp, bucketFinderVerboseOutput_tmp = self.bucketFinder.process(url,js_endpoint)
				bucketFinderOutput.append(bucketFinderOutput_tmp)
				bucketFinderVerboseOutput.append(bucketFinderVerboseOutput_tmp)

				firebaseFinderOutput_tmp, firebaseFinderVerboseOutput_tmp = self.firebaseFinder.process(url, js_endpoint)
				firebaseFinderOutput.append(firebaseFinderOutput_tmp)
				firebaseFinderVerboseOutput.append(firebaseFinderVerboseOutput_tmp)

				tokenFinderOutput_tmp, tokenFinderVerboseOutput_tmp = self.tokenFinder.process(url, js_endpoint)
				tokenFinderOutput.append(tokenFinderOutput_tmp)
				tokenFinderVerboseOutput.append(tokenFinderVerboseOutput_tmp)

				#Search urls in js file
				urls_in_js = self.helper.get_http_in_js(self.session, js_endpoint)
				urls_in_js = self.helper.checkScope(urls_in_js, self.scope)
				#We run the tool that interacts with sub_urls
				for sub_url in urls_in_js:
					if not self.helper.verifyURL(self.session, url, js_endpoint, self.error_data, 'full'):
						continue

					bucketFinderOutput_tmp, bucketFinderVerboseOutput_tmp = self.bucketFinder.process(url,sub_url)
					bucketFinderOutput.append(bucketFinderOutput_tmp)
					bucketFinderVerboseOutput.append(bucketFinderVerboseOutput_tmp)

					firebaseFinderOutput_tmp, firebaseFinderVerboseOutput_tmp = self.firebaseFinder.process(url, sub_url)
					firebaseFinderOutput.append(firebaseFinderOutput_tmp)
					firebaseFinderVerboseOutput.append(firebaseFinderVerboseOutput_tmp)

					tokenFinderOutput_tmp, tokenFinderVerboseOutput_tmp = self.tokenFinder.process(url, sub_url)
					tokenFinderOutput.append(tokenFinderOutput_tmp)
					tokenFinderVerboseOutput.append(tokenFinderVerboseOutput_tmp)

			for css_endpoint in css_in_url:
				cssFinderOutput_tmp, cssFinderVerboseOutput_tmp = self.cssChecker.process(url, css_endpoint)
				cssFinderOutput.append(cssFinderOutput_tmp)
				cssFinderVerboseOutput.append(cssFinderVerboseOutput_tmp)


			bucketFinderOutput = self.helper.normalizeList(bucketFinderOutput)
			firebaseFinderOutput = self.helper.normalizeList(firebaseFinderOutput)
			openRedirectOutput = self.helper.normalizeList(openRedirectOutput)
			endpointFinderOutput = self.helper.normalizeList(endpointFinderOutput)
			tokenFinderOutput = self.helper.normalizeList(tokenFinderOutput)
			cssFinderOutput = self.helper.normalizeList(cssFinderOutput)

			bucketFinderVerboseOutput = self.helper.normalizeList(bucketFinderVerboseOutput)
			firebaseFinderVerboseOutput = self.helper.normalizeList(firebaseFinderVerboseOutput)
			openRedirectVerboseOutput = self.helper.normalizeList(openRedirectVerboseOutput)
			endpointFinderVerboseOutput = self.helper.normalizeList(endpointFinderVerboseOutput)
			tokenFinderVerboseOutput = self.helper.normalizeList(tokenFinderVerboseOutput)
			cssFinderVerboseOutput = self.helper.normalizeList(cssFinderVerboseOutput)

			self.appendTxtInformation(url, bucketFinderVerboseOutput, firebaseFinderVerboseOutput, 
				openRedirectVerboseOutput, endpointFinderVerboseOutput, 
				tokenFinderVerboseOutput, cssFinderVerboseOutput)

			output.append(bucketFinderOutput)
			output.append(firebaseFinderOutput)
			output.append(openRedirectOutput)
			output.append(endpointFinderOutput)
			output.append(tokenFinderOutput)
			output.append(cssFinderOutput)

			output = self.helper.normalizeList(output)

			for item in output:
				print(item)



