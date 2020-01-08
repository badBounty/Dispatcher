from modules.bucketFinder import BucketFinder
from modules.tokenFinder import TokenFinder
from modules.securityHeaders import HeaderFinder
from modules.openRedirect import OpenRedirect
from modules.cssChecker import CssChecker

class FullScanner():

	bucketFinder = BucketFinder()
	tokenFinder = TokenFinder()
	headerFinder = HeaderFinder()
	openRedirect = OpenRedirect()
	cssChecker = OpenRedirect()

	def showStartScreen(self):
		print('---------------------------------------------------------------------------------------')
		print('---------------------------++++++++++++++------++++++++++++++----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++------++++++++++++++--------------------------')
		print('---------------------------+++-----------------+++--------------./*/.------------------')
		print('---./*/.-------------------+++-----------------+++-------------------------------------')
		print('---------------------------+++++++++-----------++++++++++++++--------------------------')
		print('------------./*/.----------+++++++++-----------++++++++++++++-----------./*/.----------')
		print('---------------------------+++----------------------------+++--------------------------')
		print('---------------------------+++----------------------------+++--------------------------')
		print('---------------------------+++-----------------++++++++++++++------------------./*/.---')
		print('------------./*/.----------+++-----------------++++++++++++++----./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('------------------------------------ Handerllon © -------------------------------------')
		print('                                                                                       ')
		print('---------------------- Starting full scan, this may take a while -----------------------')
		print('Searching urls...')

	def showEndScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('Finished! Please check output folder for results')


	def output(self):

		self.bucketFinder.output()
		self.tokenFinder.output()
		self.headerFinder.output()
		self.openRedirect.output()
		self.cssChecker.output()

	def run(self, urls):

		self.bucketFinder.run(urls)
		self.tokenFinder.run(urls)
		self.headerFinder.run(urls)
		self.openRedirect.run(urls)
		self.cssChecker.run(urls)