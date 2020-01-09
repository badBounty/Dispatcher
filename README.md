
# Dispatcher

This is a tool for reviewing the html code from a webpage and the javascript files within it.  

It presents several modes:

- bucketFinder: Scans code in search for s3 buckets. Once a bucket is found, the program tries some basic commands to check the permissions users have. Logging in with aws cli is recommended before running.

- tokenFinder: Searches Usernames, passwords, keys, tokens, etc. Present in html/Javascript code (Work in progress)

- headerFinder: Checks the security headers present in the webpage, this mode is the fastest and serves as data collection.

- openRedirect: Checks if the url has openRedirect vulnerability

- cssChecker: Verifies if any css files present in the url have a `response.status_code != 200` (Could cause CSS Injection)

Input urls must contain http or https

## Usage

`py dispatcher.py -m <Mode> -i <input> -t <threads (Default 3)>`

### Options

| Command  | Description  |   |
|---|---|---|
| -m  |  MODE  | - `bucketFinder`: Scans code in search of s3 buckets, then tries to execute ls and cp commands.|
|||- `tokenFinder`: Searches hidden tokens in html and javascript files|
|||- `cssChecker`: Checks if css files used in the page are valid (return code 200)|
|||- `openRedirect`: Checks if the url has a open redirect vulnerability (Currently only scanning login endpoints)|
|||- `full`: All modules at the same time|
| -t  | THREADS  | Number of threads to use, the default is 3  |
| -i | INPUT  | Input file that contains urls to be scanned (with http/https)  |
