import requests
import urllib3
import re
import sys
import subprocess
import time
import os
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BucketFinder():

	data = []
	error_data = []
	msTeamsActivated = False

	def output(self):
		df = pd.DataFrame(self.data, columns = ['SourceURL','js_reference','Bucket Name','ls allowed', 'cprm allowed'])
		df.to_csv('output/bucketFinder.csv', index = False)
		df2 = pd.DataFrame(self.error_data, columns = ['SourceURL','js_reference','Reason'])
		df2.to_csv('output/bucketFinderError.csv', index = False)

	def setMsTeams(self,msTeams):
		self.msTeamsActivated = True
		self.msTeams = msTeams

	def filterInvalids(self,some_list):
		res = []
		#------ Filter invalid matches
		for item in some_list:
			if all(char not in item for char in ['\\','=','>','<','[',']','{','}',';','(',')']):
				res.append(item)
		return res

	def configureOutput(self, url, js_endpoint, bucket_list, ls_allowed, cprm_allowed):
		#------ Adding info for output
		for bucket in bucket_list:
			ls = False
			if bucket in ls_allowed:
				ls = True
			cprm = False
			if bucket in cprm_allowed:
				cprm = True

			#Microsoft teams output
			if self.msTeamsActivated:
				if ls == True and cprm == True:
					self.msTeams.title('Bucket found!')
					self.msTeams.text('Bucket ' + bucket + ' was found at host: '+ url + ' in: ' +
							js_endpoint+' with ls and cprm allowed')
					self.msTeams.send()
				elif ls == True:
					self.msTeams.title('Bucket found!')
					self.msTeams.text('Bucket ' + bucket + ' was found at host: '+ url + ' in: ' +
							js_endpoint+' with ls allowed')
					self.msTeams.send()
				elif cprm == True:
					self.msTeams.title('Bucket found!')
					self.msTeams.text('Bucket ' + bucket + ' was found at host: '+ url + ' in: ' +
							js_endpoint+' with cprm allowed')
					self.msTeams.send()

			#Adding to data for exporting
			self.data.append([url, js_endpoint, bucket, ls, cprm])

	def get_buckets(self, url, host):

		try:
			response = requests.get(url, verify = False)
		except:
			print('Url: ' + url + ' could not be accessed')
			self.error_data.append([host,url,'Invalid js file'])
			return []

		if response.status_code == 404:
			print('Url: ' + url + ' returned 404')
			self.error_data.append([host,url,'Returned 404'])
			return []

		responseText = response.text
		#print(responseText)

		#Buckets can come in different ways
		#Way 1: http<s>://s3.amazonaws.com/bucketName
		#Way 2: http<s>://bucketName.s3.amazonaws.com
		#Way 3: //bucketName.s3.amazonaws.com

		#---------Way I----------
		bucketsFirstHTTPS = re.findall('"https://s3.amazonaws.com(.+?)"', responseText)
		bucketsFirstHTTPS = self.filterInvalids(bucketsFirstHTTPS)
		bucketsFirstHTTP = re.findall('"http://s3.amazonaws.com(.+?)"', responseText)
		bucketsFirstHTTP = self.filterInvalids(bucketsFirstHTTP)

		#---------Way II----------
		bucketsSecondHTTPS = re.findall('"https://(.+?).s3.amazonaws.com', responseText)
		bucketsSecondHTTPS = self.filterInvalids(bucketsSecondHTTPS)
		bucketsSecondHTTP = re.findall('"http://(.+?).s3.amazonaws.com', responseText)
		bucketsSecondHTTP = self.filterInvalids(bucketsSecondHTTP)

		#---------Way III---------
		bucketsThird = re.findall('\"//(.+?).s3.amazonaws.com', responseText)
		bucketsThird = self.filterInvalids(bucketsThird)

		bucket_list = bucketsFirstHTTP + bucketsSecondHTTP + bucketsFirstHTTPS + bucketsSecondHTTPS + bucketsThird
		bucket_list = list(dict.fromkeys(bucket_list))

		for i in range (len(bucket_list)):
			bucket_list[i] = bucket_list[i].replace('/','')

		if len(bucket_list) == 0:
			print('No buckets found at: ' + url)

		return bucket_list

	#--------------------- Get buckets that allow ls ---------------------
	def get_ls_buckets(self,bucket_list):
		ls_allowed_buckets = []
		for bucket in bucket_list:
			try:
				output = subprocess.check_output('aws s3 ls s3://' + bucket, shell = True, stderr = subprocess.DEVNULL)
				ls_allowed_buckets.append(bucket)
			except subprocess.CalledProcessError:
				print('Bucket ' + bucket + ' has ls blocked')

		return ls_allowed_buckets

	#--------------------- Get buckets that allow mv and rm ---------------------
	def get_cprm_buckets(self,bucket_list):
		cprm_allowed_buckets = []
		for bucket in bucket_list:
			try:
				output = subprocess.check_output('aws s3 cp test.txt s3://' + bucket, shell = True, stderr = subprocess.DEVNULL)
				subprocess.check_output('aws s3 rm s3://' + bucket + '/test.txt', shell = True)
				cprm_allowed_buckets.append(bucket)
			except subprocess.CalledProcessError as e:
				print('Bucket ' + bucket + ' has cprm blocked')

		return cprm_allowed_buckets

	def get_js_files(self,url):

		try:
			get_response = requests.get(url, verify = False)
		except Exception:
			return []
			
		get_text = get_response.text

		js_found = re.findall('([^\s",\']+)\.js', get_text)
		js_found = self.filterInvalids(js_found)
		for i in range (len(js_found)):
			#We add the .js that was removed at the regex
			js_found[i] = js_found[i] + '.js'

		host = get_response.url.split('/')
		host_protocol = host[0]
		host_name = host[2]
		only_hostname = host_protocol + '//' + host_name

		for i in range (len(js_found)):
			if js_found[i][:2] == '//':
				js_found[i] = 'https:' + js_found[i]
			elif js_found[i][:1] == '/':
				js_found[i] = only_hostname + js_found[i]
			elif js_found[i][:1] != 'h':
				js_found[i] = 'https://' + js_found[i]

		#print(str(len(js_found)) + ' js files were found!')
		return(js_found)

	def check_buckets(self, hostname, subname, bucket_list):
		if len(bucket_list)>0:
			print('The following bucket/s were found at ' + subname + ' :')
			print(bucket_list)

			#print('Checking bucket/s that allow ls...')
			ls_allowed = self.get_ls_buckets(bucket_list)
			#print('Checking bucket/s that allow cprm...')
			cprm_allowed = self.get_cprm_buckets(bucket_list)
			access_denied = list(set(bucket_list) - set(ls_allowed) - set(cprm_allowed)) 

			#print('Buckets that allowed ls are the following:')
			print(ls_allowed)
			#print('Buckets that allowed cp and rm are the following:')
			print(cprm_allowed)
			#print('No permissions buckets:')
			print(access_denied)

			self.configureOutput(hostname, subname, bucket_list, ls_allowed, cprm_allowed)

	
	def showStartScreen(self):
		print('---------------------------------------------------------------------------------------')
		print('---------------------------++++++++++++++------++++++++++++++----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++------++++++++++++++--------------------------')
		print('---------------------------+++----------------------------+++---./*/.------------------')
		print('---./*/.-------------------+++----------------------------+++--------------------------')
		print('---------------------------++++++++++++++------++++++++++++++--------------------------')
		print('------------./*/.----------++++++++++++++------++++++++++++++-----------./*/.----------')
		print('--------------------------------------+++-----------------+++--------------------------')
		print('--------------------------------------+++-----------------+++--------------------------')
		print('---------------------------++++++++++++++------++++++++++++++------------------./*/.---')
		print('------------./*/.----------++++++++++++++------++++++++++++++----./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('------------------------------------ Handerllon © -------------------------------------')
		print('                                                                                       ')
		print('-------------------------- Starting vulnerable bucket finder --------------------------')
		print('Searching buckets on input...')


	#Receives an urlList
	def run(self,urls):
		
		for url in urls:
			print('Searching '+ url)

			buckets_in_html = self.get_buckets(url, 'html code')
			self.check_buckets(url, 'html code', buckets_in_html)

			js_in_url = self.get_js_files(url)

			#print(js_in_url)
			
			for js_endpoint in js_in_url:
				# Searching for buckets
				bucket_list = self.get_buckets(js_endpoint, url)
				self.check_buckets(url, js_endpoint, bucket_list)

		self.output()


		print('-------------------------- Finished! --------------------------')
		print('###__Found buckets sent to output.csv, errors sent to ErrorOutput.csv__###')