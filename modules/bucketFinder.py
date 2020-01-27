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

class BucketFinder():

	def __init__(self):
		self.scanned_targets = []
		self.data = []
		self.error_data = []
		self.msTeamsActivated = False
		self.outputActivated = False
		self.helper = Helper()


	def activateOutput(self):
		self.outputActivated = True

	def showStartScreen(self):
		print('---------------------------------------------------------------------------------------')
		print('----------------------------++++++++++++-------++++++++++++++----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++------++++++++++++++--------------------------')
		print('---------------------------+++----------------------------+++---./*/.------------------')
		print('---./*/.-------------------+++----------------------------+++--------------------------')
		print('---------------------------+++++++++++++-------++++++++++++++--------------------------')
		print('------------./*/.----------++++++++++++++------++++++++++++++-----------./*/.----------')
		print('--------------------------------------+++-----------------+++--------------------------')
		print('--------------------------------------+++-----------------+++--------------------------')
		print('---------------------------++++++++++++++------++++++++++++++------------------./*/.---')
		print('------------./*/.-----------+++++++++++++------++++++++++++++----./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('-------------------------- Starting vulnerable bucket finder --------------------------')
		print('Searching buckets on input...')

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
			if all(char not in item for char in ['\\','=','>','<','[',']','{','}',';','(',')']):
				res.append(item)
		return res

	def configureOutput(self, url, js_endpoint, bucket_list, ls_allowed, cprm_allowed, does_not_exist):
		#------ Adding info for output
		for bucket in bucket_list:
			ls = False
			if bucket in ls_allowed:
				ls = True
			cprm = False
			if bucket in cprm_allowed:
				cprm = True
			not_exist = False
			if bucket in does_not_exist:
				not_exist = True

			if ls == True and cprm == True:
				self.data.append(['Misconfigured S3 bucket', url, js_endpoint, 'Bucket '+ bucket + ' has copy, remove and ls available for authenticated users'])
				if self.msTeamsActivated:
					self.msTeams.title('Bucket found!')
					self.msTeams.text('Bucket ' + bucket + ' was found at host: '+ url + ' in: ' +
							js_endpoint+' with ls and cprm allowed')
					self.msTeams.send()
			elif ls == True:
				self.data.append(['Misconfigured S3 bucket', url, js_endpoint, 'Bucket '+ bucket + ' has ls available for authenticated users'])
				if self.msTeamsActivated:
					self.msTeams.title('Bucket found!')
					self.msTeams.text('Bucket ' + bucket + ' was found at host: '+ url + ' in: ' +
							js_endpoint+' with ls allowed')
					self.msTeams.send()
			elif cprm == True:
				self.data.append(['Misconfigured S3 bucket', url, js_endpoint, 'Bucket '+ bucket + ' has copy and remove available for authenticated users'])
				if self.msTeamsActivated:
					self.msTeams.title('Bucket found!')
					self.msTeams.text('Bucket ' + bucket + ' was found at host: '+ url + ' in: ' +
							js_endpoint+' with cprm allowed')
					self.msTeams.send()
			elif not_exist == True:
				self.data.append(['Misconfigured S3 bucket', url, js_endpoint, 'Bucket '+ bucket + ' does not exist but resources are being loaded from it, bucket takeover possible'])
				if self.msTeamsActivated:
					self.msTeams.title('Bucket found!')
					self.msTeams.text('Bucket ' + bucket + ' was found at host: '+ url + ' in: ' +
							js_endpoint+' with does not exist error')
					self.msTeams.send()

	def get_buckets(self, session, url, host):

		if url in self.scanned_targets:
			return []

		self.scanned_targets.append(url)

		try:
			response = session.get(url, verify = False, timeout = 3)
		except:
			return []

		#print(url)
		
		if response.status_code == 404:
			print('Url: ' + url + ' returned 404')
			self.error_data.append(['s3bucket',host,url,'Returned 404'])
			return []

		#Buckets can come in different ways
		#Way 1: http<s>://s3.amazonaws.com/bucketName
		#Way 2: http<s>://bucketName.s3.amazonaws.com
		#Way 3: //bucketName.s3.amazonaws.com
		#Way 4: https://s3-area.amazonaws.com/<bucketName>/

		#---------Way I----------
		bucketsFirstHTTPS = re.findall('"https://s3.amazonaws.com([^\"/,]+)"', response.text)
		bucketsFirstHTTPS = self.filterInvalids(bucketsFirstHTTPS)
		bucketsFirstHTTP = re.findall('"http://s3.amazonaws.com([^\"/,]+)"', response.text)
		bucketsFirstHTTP = self.filterInvalids(bucketsFirstHTTP)

		#---------Way II----------
		bucketsSecondHTTPS = re.findall('https://([^\"/,]+).s3.amazonaws.com', response.text)
		bucketsSecondHTTPS = self.filterInvalids(bucketsSecondHTTPS)
		bucketsSecondHTTP = re.findall('http://([^\"/,]+).s3.amazonaws.com', response.text)
		bucketsSecondHTTP = self.filterInvalids(bucketsSecondHTTP)

		#---------Way III---------
		bucketsThird = re.findall('\"//(.+?).s3.amazonaws.com', response.text)
		bucketsThird = self.filterInvalids(bucketsThird)

		#---------Way IV----------
		bucketsFourth = re.findall('amazonaws.com/(.+?)/', response.text)
		bucketsFourth = self.filterInvalids(bucketsFourth)

		bucket_list = bucketsFirstHTTP + bucketsSecondHTTP + bucketsFirstHTTPS + bucketsSecondHTTPS + bucketsThird + bucketsFourth
		bucket_list = list(dict.fromkeys(bucket_list))

		for i in range (len(bucket_list)):
			bucket_list[i] = bucket_list[i].replace('/','')

		return bucket_list

	#--------------------- Get buckets that allow ls ---------------------
	def get_ls_buckets(self,bucket_list):
		ls_allowed_buckets = []
		does_not_exist_buckets = []
		for bucket in bucket_list:
			if (any(x.isupper() for x in bucket)):
				continue
			try:
				output = subprocess.check_output('aws s3 ls s3://' + bucket, shell = True, stderr = subprocess.STDOUT)
				#print(output)
				ls_allowed_buckets.append(bucket)
			except subprocess.CalledProcessError as e:
				if 'does not exist' in e.output.decode():
					does_not_exist_buckets.append(bucket)
				continue

		return ls_allowed_buckets, does_not_exist_buckets

	#--------------------- Get buckets that allow mv and rm ---------------------
	def get_cprm_buckets(self,bucket_list):
		cprm_allowed_buckets = []
		for bucket in bucket_list:
			try:
				output = subprocess.check_output('aws s3 cp test.txt s3://' + bucket, shell = True, stderr = subprocess.DEVNULL)
				subprocess.check_output('aws s3 rm s3://' + bucket + '/test.txt', shell = True)
				cprm_allowed_buckets.append(bucket)
			except subprocess.CalledProcessError as e:
				continue

		return cprm_allowed_buckets

	def check_buckets(self, hostname, subname, bucket_list):
		if len(bucket_list)>0:
			print('The following bucket/s were found at ' + subname + ' :')
			print(bucket_list)

			#print('Checking bucket/s that allow ls...')
			ls_allowed, does_not_exist = self.get_ls_buckets(bucket_list)
			#print('Checking bucket/s that allow cprm...')
			cprm_allowed = self.get_cprm_buckets(bucket_list)
			access_denied = list(set(bucket_list) - set(ls_allowed) - set(cprm_allowed) - set(does_not_exist))

			self.configureOutput(hostname, subname, bucket_list, ls_allowed, cprm_allowed, does_not_exist)

	def process(self, session, url):

		buckets_in_html = self.get_buckets(session, url, url)
		self.check_buckets(url, 'html code', buckets_in_html)

		js_in_url = self.helper.get_js_in_url(session, url)
			
		for js_endpoint in js_in_url:
			# Searching for buckets
			bucket_list = self.get_buckets(session, js_endpoint, url)
			self.check_buckets(url, js_endpoint, bucket_list)

			#Search urls in js file
			http_in_js = self.helper.get_http_in_js(session, url)

			for http_endpoint in http_in_js:
				bucket_list = self.get_buckets(session, http_endpoint, url)
				self.check_buckets(url, http_endpoint, bucket_list)

	#Receives an urlList
	def run(self, urls):

		session = requests.Session()
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

		session.headers.update(headers)
		
		for url in urls:
			if self.outputActivated:
				print('Scanning '+ url)

			self.process(session, url)