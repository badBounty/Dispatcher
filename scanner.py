import pymsteams
import os
import argparse
import numpy as np
import threading
from bucketFinder import BucketFinder
from tokenFinder import TokenFinder
from securityHeaders import HeaderFinder
from openRedirect import OpenRedirect
from cssChecker import CssChecker

def fullScan(bucketFinder, tokenFinder, headerFinder, openRedirect, urls):
	bucketFinder.run(urls)
	tokenFinder.run(urls)
	headerFinder.run(urls)
	openRedirect.run(urls)
	cssChecker.run(urls)

parser = argparse.ArgumentParser()

parser.add_argument('-m', '--mode', help = "Available options are bucketFinder, tokenFinder, headerFinder, cssChecker or full for all three. Refer to documentation for more info",
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
			t.join()
	except KeyboardInterrupt:
		bucketFinder.output()
	bucketFinder.showEndScreen()

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
			t.join()
	except KeyboardInterrupt:
		tokenFinder.output()
	tokenFinder.showEndScreen()

#------------------ Header Finder --------------------
elif args.mode == 'headerFinder':
	headerFinder = HeaderFinder()
	headerFinder.showStartScreen()
	try:
		#threads = []
		for i in range(args.threads):
			t = threading.Thread(target = headerFinder.run, args = (urls[i],))
			#threads.append(t)
			t.start()
			t.join()
	except KeyboardInterrupt:
		headerFinder.output()
	headerFinder.showEndScreen()

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
			t.join()
	except KeyboardInterrupt:
		openRedirect.output()
	openRedirect.showEndScreen()

#------------------- Css Checker ---------------------
elif args.mode == 'cssChecker':
	cssChecker = CssChecker()
	cssChecker.showStartScreen()
	try:
		threads = []
		for i in range(args.threads):
			t = threading.Thread(target = cssChecker.run, args = (urls[i],))
			threads.append(t)
			t.start()
			t.join()
	except KeyboardInterrupt:
		cssChecker.output()
	cssChecker.showEndScreen()

#----------------------- All -------------------------
elif args.mode == 'full':
	bucketFinder = BucketFinder()
	tokenFinder = TokenFinder()
	headerFinder = HeaderFinder()
	openRedirect = OpenRedirect()
	cssChecker = OpenRedirect()
	try:
		for i in range(args.threads):
			t = threading.Thread(target = fullScan, args = (bucketFinder, tokenFinder, headerFinder, openRedirect, cssChecker, urls[i],))
			t.start()
			t.join()
	except KeyboardInterrupt:
		bucketFinder.output()
		tokenFinder.output()
		headerFinder.output()
		openRedirect.output()