import requests
import re

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