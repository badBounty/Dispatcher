
# Dispatcher

Dispatcher tries to find vulnerabilities not covered by regular scanners (Nessus, acunetix). This is a work in progress so any feedback is appreciated.  

Available modules are listed under Options. Oputput will be under output folder.

## Usage

`py dispatcher.py -m <Mode> -i <input>`

## Requirements

- `python 3.x`
- `pip`

## Installation

- `git clone https://github.com/badBounty/Dispatcher.git`
- `pip install -r requirements.txt`

If `s3bucket` module is going to be used, it is recommended to have a `awscli` account configured. This is because, generally, vulnerable s3 buckets are configured to be accessed by `authenticated-users`, which means ANY aws user.

This can be done by following these steps.

- `pip install awscli`
- `aws configure`
- Follow prompts

### Options

| Command  | Description  |   |
|---|---|---|
| -m  |  MODE  | - `s3bucket`: Scans code in search of s3 buckets, then tries to execute ls and cp commands.|
|||- `token`: Searches hidden tokens in html and javascript files|
|||- `header`: Generates a csv file with the security headers present on each url|
|||- `css`: Checks if css files used in the page are valid (return code 200)|
|||- `openred`: Checks if the url has a open redirect vulnerability (Currently only scanning login endpoints)|
|||- `full`: All modules at the same time|
| -t  | THREADS  | Number of threads to use, the default is 3  |
| -i | INPUT  | Input file that contains urls to be scanned (with http/https)  |
