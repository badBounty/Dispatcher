import pymsteams
import os
import argparse
import numpy as np
import threading
from bucketFinder import BucketFinder
from tokenFinder import TokenFinder
from securityHeaders import HeaderFinder
from openRedirect import OpenRedirect


parser = argparse.ArgumentParser()

parser.add_argument('-m', '--mode', help = "Available options are bucketFinder, tokenFinder, headerFinder or full for all three. Refer to documentation for more info",
					required = True,
					action = 'store')
parser.add_argument('-i', '--input', help = "Input file that contains urls to be scanned (With HTTP/HTTPS)",
					required = True,
					action = 'store')

parser.add_argument('-t','--threads', help = "Number of threads for the program",
					required = False,
					action = 'store',
					default = 3,
					type = int)

#parser.add_argument('-t', '--teams', help = "Url for MSTeams webhook, used for notifications",
#					required = False,
#					action = 'store',
#					default = 'False')
#if args.teams != 'False':
	#msTeams = pymsteams.connectorcard(args.teams)
	#bucketFinder.setMsTeams(msTeams)

args = parser.parse_args()

urls = []
with open(args.input) as fp:
	lines = fp.read()
	urls = lines.split('\n')

urls = filter(None, urls) # fastest
urls = list(urls)

urls = np.array_split(urls,args.threads)
for i in range(len(urls)):
	urls[i] = urls[i].tolist()

if not os.path.exists('output'):
	os.makedirs('output')


#------------------ Bucket Finder --------------------
if args.mode == 'bucketFinder':
	bucketFinder = BucketFinder()
	bucketFinder.showStartScreen()
	try:
		threads = []
		for i in range(args.threads):
			t = threading.Thread(target = bucketFinder.run, args = (urls[i],))
			threads.append(t)
			t.start()
	except KeyboardInterrupt:
		openRedirect.output()

#------------------ Token Finder --------------------
elif args.mode == 'tokenFinder':
	tokenFinder = TokenFinder()
	tokenFinder.showStartScreen()
	try:
		threads = []
		for i in range(args.threads):
			t = threading.Thread(target = tokenFinder.run, args = (urls[i],))
			threads.append(t)
			t.start()
	except KeyboardInterrupt:
		openRedirect.output()

#------------------ Header Finder --------------------
elif args.mode == 'headerFinder':
	headerFinder = HeaderFinder()
	headerFinder.showStartScreen()
	try:
		threads = []
		for i in range(args.threads):
			t = threading.Thread(target = headerFinder.run, args = (urls[i],))
			threads.append(t)
			t.start()
	except KeyboardInterrupt:
		openRedirect.output()

#------------------ Open Redirect --------------------
elif args.mode == 'openRedirect':
	openRedirect = OpenRedirect()
	openRedirect.showStartScreen()
	try:
		threads = []
		for i in range(args.threads):
			t = threading.Thread(target = openRedirect.run, args = (urls[i],))
			threads.append(t)
			t.start()
	except KeyboardInterrupt:
		openRedirect.output()
		
#------------------ All --------------------
elif args.mode == 'full':
	bucketFinder = BucketFinder()
	tokenFinder = TokenFinder()
	headerFinder = HeaderFinder()
	openRedirect = OpenRedirect()
	try:
		bucketFinder.run(urls)
		tokenFinder.run(urls)
		headerFinder.run(urls)
		openRedirect.run(urls)
	except KeyboardInterrupt:
		bucketFinder.output()
		tokenFinder.output()
		headerFinder.output()
		openRedirect.output()
