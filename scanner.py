import pymsteams
import os
import argparse
from bucketFinder import BucketFinder
from tokenFinder import TokenFinder
from securityHeaders import HeaderFinder

bucketFinder = BucketFinder()
tokenFinder = TokenFinder()
headerFinder = HeaderFinder()

parser = argparse.ArgumentParser()

parser.add_argument('-m', '--mode', help = "Mode, available options are bucketFinder, tokenFinder, headerFinder or full for all three",
					required = 'True',
					action = 'store')
parser.add_argument('-i', '--input', help = "Input file that contains urls to be scanned (With HTTP/HTTPS)",
					required = 'True',
					action = 'store')

args = parser.parse_args()

urls = []
with open(args.input) as fp:
	lines = fp.read()
	urls = lines.split('\n')

print(urls)

#msTeams = pymsteams.connectorcard("")
#bucketFinder.setMsTeams(msTeams)
#bucketFinder.run(urls)

if not os.path.exists('output'):
	os.makedirs('output')

if args.mode == 'bucketFinder':
	bucketFinder.run(urls)
elif args.mode == 'tokenFinder':
	tokenFinder.run(urls)
elif args.mode == 'headerFinder':
	headerFinder.run(urls)
elif args.mode == 'full':
	bucketFinder.run(urls)
	tokenFinder.run(urls)
	headerFinder.run(urls)