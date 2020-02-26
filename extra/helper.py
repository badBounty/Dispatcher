import requests
import re
import math

class Helper():

	# Regex used
	regex_str = r"""
  		(?:"|')                               # Start newline delimiter
  		(
    		((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    		[^"'/]{1,}\.                        # Match a domainname (any character + dot)
    		[a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    		|
    		((?:/|\.\./|\./)                    # Start with /,../,./
    		[^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
    		[^"'><,;|()]{1,})                   # Rest of the characters can't be
    		|
    		([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    		[a-zA-Z0-9_\-/]{1,}                 # Resource name
    		\.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
    		|
    		([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
    		[a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
    		|
    		([a-zA-Z0-9_\-]{1,}                 # filename
    		\.(?:php|asp|aspx|jsp|json|
    		     action|html|js|txt|xml)        # . + extension
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
  		)
  		(?:"|')                               # End newline delimiter
		"""

	invalid_substrings = ['.png','.jpg','.mp4','.mp3']

	def get_js_in_url(self, session, url):
		regex = re.compile(self.regex_str, re.VERBOSE)
		try:
			response = session.get(url, verify = False, timeout = 3)
		except Exception:
			return []

		all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
		js_endpoints = list()
		for match in all_matches:
			if '.js' in list(match)[0] and 'http' in list(match)[0]:
				js_endpoints.append(list(match)[0])

		return js_endpoints

	def get_http_in_js(self, session, url):
		regex = re.compile(self.regex_str, re.VERBOSE)

		http_endpoints = list()
		try:
			response = session.get(url, verify = False, timeout = 3)
		except Exception:
			return http_endpoints
		matches_in_js = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
		for match in matches_in_js:
			if 'http' in list(match)[0] and '.js' not in list(match)[0] and '.css' not in list(match)[0]:
				if not any(substring in list(match)[0] for substring in self.invalid_substrings):
					http_endpoints.append(list(match)[0])

		return http_endpoints

	def get_css_in_url(self, session, url):

		regex = re.compile(self.regex_str, re.VERBOSE)

		try:
			response = session.get(url, verify = False)
		except Exception:
			return []

		all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
		css_endpoints = list()
		for match in all_matches:
			if '.css' in list(match)[0] and 'http' in list(match)[0]:
				css_endpoints.append(list(match)[0])

		return css_endpoints

	def verifyURL(self, session, origin_url, url_to_verify, error_data, from_module):

		try:
			response = session.get(url_to_verify, verify = False, timeout = 3)
		except requests.exceptions.ConnectionError:
			print('Url: ' + url_to_verify + ' Timed out')
			error_data.append([from_module,origin_url,url_to_verify,'Timeout'])
			return False
		except requests.exceptions.ReadTimeout:
			print('Url: ' + url_to_verify + ' ReadTimed out')
			error_data.append([from_module,origin_url,url_to_verify,'Read Timeout'])
			return False
		except Exception as e:
			print('Url: ' + url_to_verify + ' Had error' + str(e))
			error_data.append([from_module,origin_url,url_to_verify,'Error' + str(e)])
			return False

		if response.status_code == 404:
			print('Url: ' + url_to_verify + ' returned 404')
			error_data.append([from_module,origin_url,url_to_verify,'Returned 404'])
			return False
		else:
			return True

	def checkScope(self, url_list, scope):

		if scope == 'None':
			return url_list
		else:
			tmp = list()
			for url in url_list:
				split_url = url.split('/')
				#The hostname will be position 2
				if scope in split_url[2]:
					tmp.append(url)

		return tmp

	def sufficientStringEntropy(self, string):

		"""Calculate the entropy of a string."""
		entropy = 0
		for number in range(256):
			length = len(string.encode('utf-8'))
			result = float(string.encode('utf-8').count(number)) / length
			if result != 0:
				entropy = entropy - result * math.log(result, 2)

		if entropy >= 4:
			return True
		else:
			return False