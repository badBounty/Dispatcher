import pymsteams
import os
import argparse
import numpy as np
import pandas as pd
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

parser.add_argument('-mst','--msTeams', help = "MsTeams webhook",
					required = False,
					action = 'store')

args = parser.parse_args()

# Create output folder
if not os.path.exists('output'):
	os.makedirs('output')

#Create output/InputName Folder
inputFileName = str(args.input).split('/')
outputFolderName = inputFileName[len(inputFileName)-1].replace('.txt','')
if not os.path.exists('output/'+ outputFolderName):
	os.makedirs('output/'+ outputFolderName)

#Read urls from input
urls = []
with open(args.input) as fp:
	lines = fp.read()
	urls = lines.split('\n')

#Filter empty spaces
urls = filter(None, urls)
urls = list(urls)
urls = list(dict.fromkeys(urls))

# Generating output
def generateOutput():
	main_df.to_csv('output/'+ outputFolderName +'/output.csv', index = False)
	main_error_df.to_csv('output/'+ outputFolderName +'/error.csv', index = False)

#Create a dataframe data can be appended to it
main_df = pd.DataFrame(columns = ['Vulnerability','MainUrl','Reference','Description'])
main_error_df = pd.DataFrame(columns = ['Module','MainUrl','Reference','Reason'])

if args.msTeams:
	teamsConnection = pymsteams.connectorcard(str(args.msTeams))

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
	main_errpr_df = main_error_df.append(error_df)
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
	main_errpr_df = main_error_df.append(error_df)
	generateOutput()
	tokenFinder.showEndScreen()

#------------------ Header Finder --------------------
elif args.mode == 'header':
	headerFinder = HeaderFinder()
	headerFinder.showStartScreen()
	headerFinder.activateOutput()
	try:
		headerFinder.run(urls, outputFolderName)
	except KeyboardInterrupt:
		pass
	#data_df, error_df = headerFinder.output()
	#main_df = main_df.append(data_df)
	#main_errpr_df = main_error_df.append(error_df)
	#generateOutput()
	headerFinder.output()
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
	main_errpr_df = main_error_df.append(error_df)
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
	main_errpr_df = main_error_df.append(error_df)
	generateOutput()
	cssChecker.showEndScreen()

#----------------------- Full -------------------------
elif args.mode == 'full':
	fullScanner = FullScanner()
	if args.msTeams:
		fullScanner.activateMSTeams(teamsConnection)
	fullScanner.showStartScreen()
	try:
		fullScanner.run(urls, outputFolderName)
	except KeyboardInterrupt:
		pass
	#
	data_df, error_df = fullScanner.output(outputFolderName)
	main_df = main_df.append(data_df)
	main_errpr_df = main_error_df.append(error_df)
	generateOutput()
	fullScanner.showEndScreen()