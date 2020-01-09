
# Dispatcher

## Usage

`py dispatcher.py -m <Mode> -i <input> -t <threads (Default 3)>`

### Options

| Command  | Description  |   |
|---|---|---|
| -m  |  MODE  | - `bucketFinder`: Scans code in search of s3 buckets, then tries to execute ls and cp commands.|
|||- `tokenFinder`: Searches hidden tokens in html and javascript files|
|||- `headerFinder`: Generates a csv file with the security headers present on each url|
|||- `cssChecker`: Checks if css files used in the page are valid (return code 200)|
|||- `openRedirect`: Checks if the url has a open redirect vulnerability (Currently only scanning login endpoints)|
|||- `full`: All modules at the same time|
| -t  | THREADS  | Number of threads to use, the default is 3  |
| -i | INPUT  | Input file that contains urls to be scanned (with http/https)  |
