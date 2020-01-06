import pymsteams
import os
import argparse
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
parser.add_argument('-t', '--teams', help = "Url for MSTeams webhook, used for notifications",
					required = False,
					action = 'store',
					default = 'False')

args = parser.parse_args()

urls = []
with open(args.input) as fp:
	lines = fp.read()
	urls = lines.split('\n')

#print(urls)

if not os.path.exists('output'):
	os.makedirs('output')

#if args.teams != 'False':
	#msTeams = pymsteams.connectorcard(args.teams)
	#bucketFinder.setMsTeams(msTeams)

#### BucketFinder
if args.mode == 'bucketFinder':
	bucketFinder = BucketFinder()
	try:
		bucketFinder.run(urls)
	except KeyboardInterrupt:
		bucketFinder.output()

#### TokenFinder
elif args.mode == 'tokenFinder':
	tokenFinder = TokenFinder()
	try:
		tokenFinder.run(urls)
	except KeyboardInterrupt:
		tokenFinder.output()

#### HeaderFinder
elif args.mode == 'headerFinder':
	headerFinder = HeaderFinder()
	try:
		headerFinder.run(urls)
	except KeyboardInterrupt:
		headerFinder.output()

#### OpenRedirect
elif args.mode == 'openRedirect':
	headerFinder = HeaderFinder()
	try:
		openRedirect.run(urls)
	except KeyboardInterrupt:
		openRedirect.output()

#### All
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
