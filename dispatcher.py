import pymsteams
import os
import argparse
import numpy as np
import threading
from modules.bucketFinder import BucketFinder
from modules.tokenFinder import TokenFinder
from modules.securityHeaders import HeaderFinder
from modules.openRedirect import OpenRedirect
from modules.cssChecker import CssChecker
from modules.fullScanner import FullScanner

parser = argparse.ArgumentParser()

parser.add_argument('-m', '--mode', help = "Module to be used (s3bucket, token, header, css, openred, full), refer to README for description of each module",
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

if not os.path.exists('output'):
	os.makedirs('output')

#Read urls from input
urls = []
with open(args.input) as fp:
	lines = fp.read()
	urls = lines.split('\n')

if not os.path.exists('output/'+str(args.input)):
	os.makedirs('output/'+str(args.input))

#Filter empty spaces
urls = filter(None, urls)
urls = list(urls)

#Dividing based on thread number
urls = np.array_split(urls,args.threads)
for i in range(len(urls)):
	urls[i] = urls[i].tolist()

#------------------ Bucket Finder --------------------
if args.mode == 's3bucket':
	bucketFinder = BucketFinder()
	bucketFinder.showStartScreen()
	bucketFinder.activateOutput()
	try:
		for i in range(args.threads):
			t = threading.Thread(target = bucketFinder.run, args = (urls[i],str(args.input),))
			t.start()
			t.join()
	except KeyboardInterrupt:
		bucketFinder.output(str())
	bucketFinder.showEndScreen()

#------------------ Token Finder --------------------
elif args.mode == 'token':
	tokenFinder = TokenFinder()
	tokenFinder.showStartScreen()
	tokenFinder.activateOutput()
	try:
		for i in range(args.threads):
			t = threading.Thread(target = tokenFinder.run, args = (urls[i],str(args.input),))
			t.start()
			t.join()
	except KeyboardInterrupt:
		tokenFinder.output()
	tokenFinder.showEndScreen()

#------------------ Header Finder --------------------
elif args.mode == 'header':
	headerFinder = HeaderFinder()
	headerFinder.showStartScreen()
	headerFinder.activateOutput()
	try:
		for i in range(args.threads):
			t = threading.Thread(target = headerFinder.run, args = (urls[i],str(args.input),))
			t.start()
			t.join()
	except KeyboardInterrupt:
		headerFinder.output()
	headerFinder.showEndScreen()

#------------------ Open Redirect --------------------
elif args.mode == 'openred':
	openRedirect = OpenRedirect()
	openRedirect.showStartScreen()
	openRedirect.activateOutput()
	try:
		for i in range(args.threads):
			t = threading.Thread(target = openRedirect.run, args = (urls[i],str(args.input),))
			t.start()
			t.join()
	except KeyboardInterrupt:
		openRedirect.output()
	openRedirect.showEndScreen()

#------------------- Css Checker ---------------------
elif args.mode == 'css':
	cssChecker = CssChecker()
	cssChecker.showStartScreen()
	cssChecker.activateOutput()
	try:
		for i in range(args.threads):
			t = threading.Thread(target = cssChecker.run, args = (urls[i],str(args.input),))
			t.start()
			t.join()
	except KeyboardInterrupt:
		cssChecker.output()
	cssChecker.showEndScreen()

#----------------------- Full -------------------------
elif args.mode == 'full':
	fullScanner = FullScanner()
	fullScanner.showStartScreen()
	try:
		for i in range(args.threads):
			t = threading.Thread(target = fullScanner.run, args = (urls[i],str(args.input),))
			t.start()
			t.join()
	except KeyboardInterrupt:
		fullScanner.output()
	fullScanner.showEndScreen()