import os
import requests
import re
import pandas as pd

from extra.helper import Helper

class TokenFinder():

	def __init__(self, SESSION):
		self.scanned_targets = []

		self.data = []
		self.error_data = []
		self.outputActivated = False

		self.helper = Helper()

		self.session = SESSION

	def activateOutput(self):
		self.outputActivated = True

	def showStartScreen(self):

		print('---------------------------------------------------------------------------------------')
		print('---------------------------++++++++++++++------++++++++++++++----------./*/.-----------')
		print('--------------------./*/.--++++++++++++++------++++++++++++++--------------------------')
		print('--------------------------------++++-----------+++--------------./*/.------------------')
		print('---./*/.------------------------++++-----------+++-------------------------------------')
		print('--------------------------------++++-----------+++++++++++-----------------------------')
		print('------------./*/.---------------++++-----------+++++++++++--------------./*/.----------')
		print('--------------------------------++++-----------+++-------------------------------------')
		print('--------------------------------++++-----------+++-------------------------------------')
		print('--------------------------------++++-----------+++-----------------------------./*/.---')
		print('------------./*/.---------------++++-----------+++---------------./*/.-----------------')
		print('---------------------------------------------------------------------------------------')
		print('                                                                                       ')
		print('----------------------------------- Handerllon ©_© ------------------------------------')
		print('                                                                                       ')
		print('-------------------------------- Starting token finder --------------------------------')
		print('Searching sensitive info on input...')

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

		return http_endpoints

	#Searches certain keywords on site
	def tokenProcess(self, session, host, url):

		output = []

		if url in self.scanned_targets:
			return output

		self.scanned_targets.append(url)

		try:
			response = session.get(url, verify = False)
		except:
			return output

		if response.status_code == 404:
			print('Url: ' + url + ' returned 404')
			self.error_data.append(['token', host, url, 'Returned 404'])
			return output

		#Generic tokens
		licence_key = re.findall('license_key:"(.+?)"', response.text)
		if len(licence_key) > 0:
			for value in licence_key:
				self.data.append(['Information disclosure', host , url , 'The following licence_key was found: ' + value])
				output.append('Token finder found license_key: ' + value + 'at ' + url)

		api_key = re.findall('api_key:"(.+?)"', response.text)		
		if len(api_key) > 0:
			for value in api_key:
				self.data.append(['Information disclosure', host , url , 'The following key was found: ' + value])
				output.append('Token finder found api_key: ' + value + 'at ' + url)

		authorization = re.findall('authorization:"(.+?)"', response.text)
		if len(authorization) > 0:
			for value in authorization:
				self.data.append(['Information disclosure', host , url , 'The following auth_token was found: ' + value])
				output.append('Token finder found auth token: ' + value + 'at ' + url)

		access_token = re.findall('access_token:"(.+?)"', response.text)
		if len(access_token) > 0:
			for value in access_token:
				self.data.append(['Information disclosure', host , url , 'The following access_token was found: ' + value])
				output.append('Token finder found access token: ' + value + 'at ' + url)

		access_token2 = re.findall('access-token:"(.+?)"', response.text)
		if len(access_token2) > 0:
			for value in access_token2:
				self.data.append(['Information disclosure', host , url , 'The following access-token was found: ' + value])
				output.append('Token finder found access token: ' + value + 'at ' + url)

		token_1 = re.findall('Token:"(.+?)"', response.text)
		if len(token_1) > 0:
			for value in token_1:
				self.data.append(['Information disclosure', host , url , 'The following token was found: ' + value])
				output.append('Token finder found token: ' + value + 'at ' + url)

		token_2 = re.findall('token:"(.+?)"', response.text)
		if len(token_2) > 0:
			for value in token_2:
				self.data.append(['Information disclosure', host , url , 'The following token was found: ' + value])
				output.append('Token finder found token: ' + value + 'at ' + url)


		#Specific Tokens
		#------------------------------ Algolia ------------------------------
		# Algolia uses algoliasearch for connecting inside a js, we will search the key pair
		algolia_key_pair = re.findall('algoliasearch\((.+?)\);', response.text)
		if len(algolia_key_pair) > 0:
			for value in algolia_key_pair:
				self.data.append(['Information disclosure', host , url , 'The following algolia key pair was found: ' + value])
				output.append('Token finder found algolia key pair: ' + value + 'at ' + url)

		#------------------------------ Asana ------------------------------
		asana_access_token = re.findall('useAccessToken\((.+?)\);', response.text)
		if len(asana_access_token) > 0:
			for value in asana_access_token:
				self.data.append(['Information disclosure', host , url , 'The following assana access token was found: ' + value])
				output.append('Token finder found assana access token: ' + value + 'at ' + url)

		#------------------------------ AWS ------------------------------
		access_key_ids = re.findall('access_key_id:"(.+?)"', response.text)
		secret_access_key_ids = re.findall('secret_access_key_id:"(.+?)"', response.text)
		if len(access_key_ids) > 0:
			for value in access_key_ids:
				self.data.append(['Information disclosure', host , url , 'The following access_key_id was found: ' + value])
				output.append('Token finder found access_key_id: ' + value + 'at ' + url)
		if len(secret_access_key_ids) > 0:
			for value in secret_access_key_ids:
				self.data.append(['Information disclosure', host , url , 'The following secret_access_key_id was found: ' + value])
				output.append('Token finder found secret_access_key_id: ' + value + 'at ' + url)

		#------------------------------ Bitly ------------------------------
		bitlyTokens = re.findall('BitlyClient\((.+?)\);', response.text)
		if len(bitlyTokens) > 0:
			for value in bitlyTokens:
				self.data.append(['Information disclosure', host , url , 'The following bitly token was found: ' + value])
				output.append('Token finder found bitly token: ' + value + 'at ' + url)

		#------------------------------ Branchio ------------------------------
		# Here we will get the whole client definithion, which contains key and secret_key
		branchioInfo = re.findall('branchio\(\{(.+?)\}\);', response.text)
		if len(branchioInfo) > 0:
			for value in branchioInfo:
				self.data.append(['Information disclosure', host , url , 'The following branchio definition was found: ' + value])
				output.append('Token finder found branchio definition: ' + value + 'at ' + url)

		#------------------------------ Dropbox ------------------------------
		# Dropbox uses a method to set access token inside the javascript code
		dropboxToken = re.findall('Dropbox\(\{(.+?)\}\);', response.text)
		if len(dropboxToken) > 0:
			for value in dropboxToken:
				self.data.append(['Information disclosure', host , url , 'The following dropbox token was found: ' + value])
				output.append('Token finder found dropbox token: ' + value + 'at ' + url)

		#------------------------------ Firebase ------------------------------
		firebaseConfig = re.findall('firebaseConfig(.+?)\};', response.text)
		if len(firebaseConfig) > 0:
			for value in firebaseConfig:
				self.data.append(['Information disclosure', host , url , 'The following firebase config info was found: ' + value])
				output.append('Token finder found firebase config info: ' + value + 'at ' + url)

		#------------------------------ Gitlab ------------------------------
		gitlabInfo = re.findall('Gitlab\(\{(.+?)\}\);', response.text)
		if len(gitlabInfo) > 0:
			for value in gitlabInfo:
				self.data.append(['Information disclosure', host , url , 'The following gitlab personal info was found: ' + value])
				output.append('Token finder found gitlab personal info: ' + value + 'at ' + url)

		#------------------------------ Google cloud messaging ------------------------------
		gcm_key = re.findall('gcm.Sender\((.+?)\);', response.text)
		if len(gcm_key) > 0:
			for value in gcm_key:
				self.data.append(['Information disclosure', host , url , 'The following gcm api_key was found: ' + value])
				output.append('Token finder found gcm api_key: ' + value + 'at ' + url)

		#------------------------------ Google maps ------------------------------
		g_maps_key = re.findall("require('@google/maps').createClient\(\{(.+?)\}\);", response.text)
		if len(g_maps_key) > 0:
			for value in g_maps_key:
				self.data.append(['Information disclosure', host , url , 'The following google maps key was found: ' + value])
				output.append('Token finder found google maps key: ' + value + 'at ' + url)

		#------------------------------ Google autocomplete ------------------------------
		g_autocomplete_key = re.findall("googleAutoCompleteKey:Object\(\{(.+?)\}\)", response.text)
		if len(g_autocomplete_key) > 0:
			for value in g_autocomplete_key:
				self.data.append(['Information disclosure', host , url , 'The following google autocomplete key was found: ' + value])
				output.append('Token finder found google autocomplete key: ' + value + 'at ' + url)

		#------------------------------ Google recaptcha ------------------------------
		g_recaptcha_key = re.findall('GoogleRecaptcha\(\{(.+?)\}', response.text)
		if len(g_recaptcha_key) > 0:
			for value in g_recaptcha_key:
				self.data.append(['Information disclosure', host , url , 'The following google recaptcha key was found: ' + value])
				output.append('Token finder found google recaptcha key: ' + value + 'at ' + url)

		#------------------------------ Hubspot ------------------------------
		hubspot_key = re.findall('Hubspot\(\{(.+?)\}', response.text)
		if len(hubspot_key) > 0:
			for value in hubspot_key:
				self.data.append(['Information disclosure', host , url , 'The following hubspot key was found: ' + value])
				output.append('Token finder found hubspot key: ' + value + 'at ' + url)

		#------------------------------ Instagram ------------------------------
		instagram_config = re.findall('Instagram\((.+?)\)', response.text)
		if len(instagram_config) > 0:
			for value in instagram_config:
				self.data.append(['Information disclosure', host , url , 'The following instagram config info was found: ' + value])
				output.append('Token finder found instagram config info: ' + value + 'at ' + url)

		#------------------------------ Jump cloud ------------------------------
		jumpcloud_key = re.findall('JumpCloud\((.+?)\);', response.text)
		if len(jumpcloud_key) > 0:
			for value in jumpcloud_key:
				self.data.append(['Information disclosure', host , url , 'The following jumpcloud key was found: ' + value])
				output.append('Token finder found jumpcloud key: ' + value + 'at ' + url)

		#------------------------------ Mail Chimp ------------------------------
		mailchimp_key = re.findall('Mailchimp\((.+?)\);', response.text)
		if len(mailchimp_key) > 0:
			for value in mailchimp_key:
				self.data.append(['Information disclosure', host , url , 'The following mailchimp key was found: ' + value])
				output.append('Token finder found mailchimp key: ' + value + 'at ' + url)

		#------------------------------ Pagerduty ------------------------------
		pagerduty_key = re.findall('pdapiToken\((.+?)\);', response.text)
		if len(pagerduty_key) > 0:
			for value in pagerduty_key:
				self.data.append(['Information disclosure', host , url , 'The following pagerduty key was found: ' + value])
				output.append('Token finder found pagerduty key: ' + value + 'at ' + url)

		#------------------------------ Paypal ------------------------------
		paypal_config = re.findall('paypal.configure\(\{(.+?)\}\);', response.text)
		if len(paypal_config) > 0:
			for value in pagerduty_key:
				self.data.append(['Information disclosure', host , url , 'The following paypal config info was found: ' + value])
				output.append('Token finder found paypal config info: ' + value + 'at ' + url)

		#------------------------------ Razorpay ------------------------------
		razorpay_key = re.findall('Razorpay\(\{(.+?)\}\);', response.text)
		if len(razorpay_key) > 0:
			for value in razorpay_key:
				self.data.append(['Information disclosure', host , url , 'The following razorpay config info was found: ' + value])
				output.append('Token finder found razorpay config info: ' + value + 'at ' + url)

		#------------------------------ SauceLabs ------------------------------
		sauceLabs_key = re.findall('SauceLabs\(\{(.+?)\}\);', response.text)
		if len(sauceLabs_key) > 0:
			for value in sauceLabs_key:
				self.data.append(['Information disclosure', host , url , 'The following saucelab config info was found: ' + value])
				output.append('Token finder found saucelab config info: ' + value + 'at ' + url)

		#------------------------------ Sendgrid ------------------------------
		sendgrid_key = re.findall('sendgrid_api_key:"(.+?)"', response.text)
		if len(sendgrid_key) > 0:
			for value in sauceLabs_key:
				self.data.append(['Information disclosure', host , url , 'The following sendgrid key was found: ' + value])
				output.append('Token finder found sendgrid key: ' + value + 'at ' + url)

		#------------------------------ Slack ------------------------------
		slack_key = re.findall('Slack\(\{(.+?)\}\)', response.text)
		if len(slack_key) > 0:
			for value in slack_key:
				self.data.append(['Information disclosure', host , url , 'The following slack key was found: ' + value])
				output.append('Token finder found slack key: ' + value + 'at ' + url)

		#------------------------------ Spotify ------------------------------
		spotify_key = re.findall('Spotify\(\{(.+?)\}\);', response.text)
		if len(spotify_key) > 0:
			for value in spotify_key:
				self.data.append(['Information disclosure', host , url , 'The following spotify config was found: ' + value])
				output.append('Token finder found spotify config: ' + value + 'at ' + url)

		#------------------------------ Square ------------------------------
		square_key = re.findall('oauth2.accessToken = "(.+?)"', response.text)
		if len(square_key) > 0:
			for value in square_key:
				self.data.append(['Information disclosure', host , url , 'The following square key was found: ' + value])
				output.append('Token finder found square key: ' + value + 'at ' + url)

		#------------------------------ Travis ------------------------------
		travis_key = re.findall('travis.auth.github.post\(\{(.+?)\}', response.text)
		if len(travis_key) > 0:
			for value in travis_key:
				self.data.append(['Information disclosure', host , url , 'The following travis key was found: ' + value])
				output.append('Token finder found travis key: ' + value + 'at ' + url)		

		#------------------------------ Twilio ------------------------------
		twilio_account_sid = re.findall('accountSid =(.+?);', response.text)
		twilio_auth_token = re.findall('authToken =(.+?);', response.text)
		if len(twilio_account_sid) > 0:
			for value in twilio_account_sid:
				self.data.append(['Information disclosure', host , url , 'The following twilio account sid was found: ' + value])
				output.append('Token finder found twilio account sid key: ' + value + 'at ' + url)
		if len(twilio_auth_token) > 0:
			for value in travis_key:
				self.data.twilio_auth_token(['Information disclosure', host , url , 'The following twilio auth token was found: ' + value])
				output.append('Token finder found twilio auth token: ' + value + 'at ' + url)	

		#------------------------------ Twitter ------------------------------
		twitter_config = re.findall('Twitter\(\{(.+?)\}\)', response.text)
		if len(twitter_config) > 0:
			for value in twitter_config:
				self.data.twilio_auth_token(['Information disclosure', host , url , 'The following twitter config info was found: ' + value])
				output.append('Token finder found twitter config info: ' + value + 'at ' + url)	

		#------------------------------ bugsnag ------------------------------
		bugsnag = re.findall('bugsnagAPI:Object\(\{(.+?)\)\}', response.text)
		if len(bugsnag) > 0:
			for value in bugsnag:
				self.data.twilio_auth_token(['Information disclosure', host , url , 'The following bugsnag config info was found: ' + value])
				output.append('Token finder found bugsnag config info: ' + value + 'at ' + url)	

		return output

	def process(self, url, endpoint):

		output = []
		output.append(self.tokenProcess(self.session, url, endpoint))
		output = filter(None, output)
		output = [item for sublist in output for item in sublist]
		return output

	def run(self, urls):

		for url in urls:
			output = []
			print('----------------------------------------------------')
			print('Scanning '+ url)
			if not self.helper.verifyURL(self.session, url, url, self.error_data, 'full'):
				continue

			js_in_url = self.helper.get_js_in_url(self.session, url)
			#print(js_in_url)
			for js_endpoint in js_in_url:
				if not self.helper.verifyURL(self.session, url, js_endpoint, self.error_data, 'full'):
					continue
				output.append(self.tokenProcess(self.session, url, js_endpoint))

				http_in_js = self.helper.get_http_in_js(self.session, js_endpoint)
				#print(http_in_js)
				for http_endpoint in http_in_js:
					if not self.helper.verifyURL(self.session, url, http_endpoint, self.error_data, 'full'):
						continue
					output.append(self.tokenProcess(self.session, js_endpoint, http_endpoint))

			output = filter(None, output)
			output = [item for sublist in output for item in sublist]
			output = list(dict.fromkeys(output))
			for item in output:
				print(item)



