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

| Command  | Description  ||
|---|---||
| -m  | Mode  |BucketFinder|
|   |   | CssChecker |
|   |   | TokenFinder |
|   |   | OpenRedirect |
| -t  | Number of threads to use, default is 3  ||
| -i | Name of the input file  ||
