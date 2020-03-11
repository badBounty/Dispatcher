import pymsteams
import os
import argparse
import numpy as np
import pandas as pd
import threading
import sys
import datetime

from modules.bucketFinder import BucketFinder
from modules.tokenFinder import TokenFinder
from modules.securityHeaders import HeaderFinder
from modules.openRedirect import OpenRedirect
from modules.cssChecker import CssChecker
from modules.fullScanner import FullScanner
from modules.endpointFinder import EndpointFinder
from modules.firebaseFinder import FirebaseFinder

parser = argparse.ArgumentParser()

parser.add_argument('-m', '--mode', help = "Module to be used (s3bucket, token, header, css, openred, endpoint, full), refer to README for description of each module",
					required = True,
					action = 'store')
parser.add_argument('-i', '--input', help = "Input file that contains urls to be scanned (With HTTP/HTTPS)",
					required = False,
					action = 'store')
parser.add_argument('-mst','--msTeams', help = "MsTeams webhook",
					required = False,
					action = 'store')
parser.add_argument('-u', '--url', help = "Single url with http or https",
					required = False,
					action = 'store')
parser.add_argument('-o', '--output', help = "Output path (Optional)",
					required = False,
					action = 'store')

parser.add_argument('-s', '--scope', help = "Scope for the search, ex = 'yahoo'",
					required = False,
					action = 'store',
					default = 'None')
parser.add_argument('-mm', '--monitor', help = "Enables monitor mode with minutes as input",
					required = False,
					action = 'store')


args = parser.parse_args()

if not args.input and not args.url:
	print('Either -i or -u are required')
	parser.print_help()
	sys.exit(0)

urls = list()
if args.url:
	print(args.url)
	urls.append(args.url)
	inputFileName = args.url.split('/')
	try:
		inputFileName = inputFileName[2]
	except IndexError:
		print('Remember that the URL must contain http:// or https://')
		parser.print_help()
		sys.exit(0)
	inputFileName = inputFileName.replace(':','.')
	outputFolderName = inputFileName
else:
	#Read urls from input
	with open(args.input) as fp:
		lines = fp.read()
		urls = lines.split('\n')
		inputFileName = str(args.input).split('/')
		outputFolderName = inputFileName[len(inputFileName)-1].replace('.txt','')

if not args.output:
	# Create output folder
	if not os.path.exists('output'):
		os.makedirs('output')
	if not os.path.exists('output/'+ outputFolderName):
		os.makedirs('output/'+ outputFolderName)

#Filter empty spaces and duplicates
urls = filter(None, urls)
urls = list(urls)
urls = list(dict.fromkeys(urls))

now = datetime.datetime.now()
timestamp = str(now.year)+ '-'+ str(now.month) + '-'+ str(now.day)+ '-'+ str(now.hour)+ '-'+ str(now.minute)

# Generating output
def generateOutput():
	if not args.output:
		main_df.to_csv('output/'+ outputFolderName +'/'+str(timestamp)+'_'+outputFolderName+'_output.csv', index = False)
		main_error_df.to_csv('output/'+ outputFolderName +'/'+str(timestamp)+'_'+outputFolderName+'_error.csv', index = False)
	else:
		main_df.to_csv(args.output +'/'+str(timestamp)+'_'+outputFolderName+'_output.csv', index = False)
		main_error_df.to_csv(args.output +'/'+str(timestamp)+'_'+outputFolderName+'_error.csv', index = False)

#Create a dataframe data can be appended to it
main_df = pd.DataFrame(columns = ['Vulnerability','MainUrl','Reference','Description'])
main_error_df = pd.DataFrame(columns = ['Module','MainUrl','Reference','Reason'])

#Connect to microsoft teams if the -mst is enabled
if args.msTeams:
	teamsConnection = pymsteams.connectorcard(str(args.msTeams))

################### MODULE AREA #####################
# All modules work the same way in terms of running them
# Instance is created, start screen shows and program is run
# Dataframes are used for output, this will be turned into csv files later

#------------------ Bucket Finder --------------------
if args.mode == 's3bucket':
	bucketFinder = BucketFinder()
	if args.msTeams:
		bucketFinder.activateMSTeams(teamsConnection)
	bucketFinder.showStartScreen()
	bucketFinder.activateOutput()
	try:
		bucketFinder.run(urls)
	except KeyboardInterrupt:
		pass
	#
	data_df, error_df = bucketFinder.output()
	main_df = main_df.append(data_df)
	main_error_df = main_error_df.append(error_df)
	generateOutput()
	bucketFinder.showEndScreen()

#------------------ Token Finder --------------------
elif args.mode == 'token':
	tokenFinder = TokenFinder()
	tokenFinder.showStartScreen()
	tokenFinder.activateOutput()
	try:
		tokenFinder.run(urls)
	except KeyboardInterrupt:
		pass
	#
	data_df, error_df = tokenFinder.output()
	main_df = main_df.append(data_df)
	main_error_df = main_error_df.append(error_df)
	generateOutput()
	tokenFinder.showEndScreen()

#------------------ Header Finder --------------------
elif args.mode == 'header':
	headerFinder = HeaderFinder(outputFolderName)
	headerFinder.showStartScreen()
	headerFinder.activateOutput()
	try:
		headerFinder.run(urls)
	except KeyboardInterrupt:
		pass
	#HeaderFinder generates a separate csv file
	if not args.output:
		headerFinder.output('output/'+ outputFolderName +'/'+str(timestamp)+'_'+outputFolderName+'_headerFinder.csv')
	else:
		headerFinder.output(args.output +'/'+str(timestamp)+'_'+outputFolderName+'_headerFinder.csv')
	headerFinder.showEndScreen()

#------------------ Open Redirect --------------------
elif args.mode == 'openred':
	openRedirect = OpenRedirect()
	if args.msTeams:
		openRedirect.activateMSTeams(teamsConnection)
	openRedirect.showStartScreen()
	openRedirect.activateOutput()
	try:
		openRedirect.run(urls)
	except KeyboardInterrupt:
		pass
	#
	data_df, error_df = openRedirect.output()
	main_df = main_df.append(data_df)
	main_error_df = main_error_df.append(error_df)
	generateOutput()
	openRedirect.showEndScreen()

#------------------- Css Checker ---------------------
elif args.mode == 'css':
	cssChecker = CssChecker()
	if args.msTeams:
		cssChecker.activateMSTeams(teamsConnection)
	cssChecker.showStartScreen()
	cssChecker.activateOutput()
	try:
		cssChecker.run(urls)
	except KeyboardInterrupt:
		pass
	#
	data_df, error_df = cssChecker.output()
	main_df = main_df.append(data_df)
	main_error_df = main_error_df.append(error_df)
	generateOutput()
	cssChecker.showEndScreen()

#------------------- Endpoint Finder ---------------------
elif args.mode == 'endpoint':
	endpointFinder = EndpointFinder()
	if args.msTeams:
		endpointFinder.activateMSTeams(teamsConnection)
	endpointFinder.showStartScreen()
	endpointFinder.activateOutput()
	try:
		endpointFinder.run(urls)
	except KeyboardInterrupt:
		pass
	#
	data_df, error_df = endpointFinder.output()
	main_df = main_df.append(data_df)
	main_error_df = main_error_df.append(error_df)
	generateOutput()
	endpointFinder.showEndScreen()

#------------------ Header Finder --------------------
elif args.mode == 'firebase':
	firebaseFinder = FirebaseFinder()
	firebaseFinder.showStartScreen()
	firebaseFinder.activateOutput()
	try:
		firebaseFinder.run(urls)
	except KeyboardInterrupt:
		pass
	data_df, error_df = firebaseFinder.output()
	main_df = main_df.append(data_df)
	main_error_df = main_error_df.append(error_df)
	generateOutput()
	firebaseFinder.output()
	firebaseFinder.showEndScreen()


#----------------------- Full -------------------------
elif args.mode == 'full':
	fullScanner = FullScanner(outputFolderName, args.scope)
	if args.msTeams:
		fullScanner.activateMSTeams(teamsConnection)
	fullScanner.showStartScreen()
	try:
		fullScanner.run(urls)
	except KeyboardInterrupt:
		pass
	#
	if not args.output:
		data_df, error_df = fullScanner.output('output/'+ outputFolderName +'/'+outputFolderName+'_headerFinder.csv')
	else:
		data_df, error_df = fullScanner.output(args.output +'/'+outputFolderName+'_headerFinder.csv')
	main_df = main_df.append(data_df)
	main_error_df = main_error_df.append(error_df)
	generateOutput()
	fullScanner.showEndScreen()

