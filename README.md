# CleanMyCSS

## What is this
Cleanmycss is a command line python tool that
crawls an entire website and returns minified versions of the css files.
It is a super old script I developed in the past but that I still 
use to reduce the CSS from many of my websites, including large CSS files 
like bootstrap. 


## Features
- Automatic website crawler
- Downloads HTML and JS to search for CSS rule usages using `purgecss` tool
- Login screen support
- URL clustering (package urlclustering), only crawls samples when there are thousands of similar URLs

## Motivation
Websites need to be lightning fast nowadays to compete with each other.
The more resources a website needs to download, the less fast and less ranked
in search engines like Google.
Most CSS cleaners are either not so good (dont crawl entire websites) or costly.
This is a simple command line script that makes all that for you.

## Dependencies
- Install dependencies in requirements.txt

```
pip install -r requirements.txt
```

- Install [purgecss](https://purgecss.com/)

```
npm i -g purgecss
```

- Download [chromedriver](https://chromedriver.chromium.org/downloads)

## Usage

```
python clean.py -m 1000
    -u https://www.mywebsite.com
```

- Login and crawl

```
python clean.py -m 1000
    -u https://www.mywebsite.com/
    --username admin
    --password adminpassword
    --username_selector "[name='username']"
    --password_selector "[name='password']"
    --login_url https://www.mywebsite.com/accounts/login/
    --chrome ./chromedriver #assuming chromedriver is in the same directory
```

### Options
```
# Main options
-u, --url: Main URL to parse from
--chrome: Chrome driver path
-m, --max-urls: Number of max URLs to crawl, default is 30.", default=30, type=int)
# Login options
--login_url: Optional. If the login URL differs from the main parse URL
--login_btn_selector: Optional: The CSS or xpath selector for the login button
--username: Optional: the username for the login
--username_selector: Optional, The CSS or xpath selector for the username field
--password: Optional, the password for the login
--password_selector: Optional, The CSS or xpath selector for the password field
--extra_urls: Optional, extra seed URLs to crawl
```

## Results
Results are stored in `runs/` directory. CSSs files are in `runs/{runid}/cssout`.

