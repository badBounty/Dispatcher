# Scanner

Scanner is a tool for reviewing the html code from a webpage and the javascript files within it.  

It presents several modes:

- bucketFinder: Scans code in search for s3 buckets. Once a bucket is found, the program tries some basic commands to check the permissions users have. Logging in with aws cli is recommended before running.

- tokenFinder: Searches Usernames, passwords, keys, tokens, etc. Present in html/Javascript code (Work in progress)

- headerFinder: Checks the security headers present in the webpage, this mode is the fastest and serves as data collection.

Input urls must contain http or https