import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import json
from subprocess import check_output, STDOUT
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import colorama
import uuid
import os
from css_html_js_minify import css_minify
import urlclustering
import random
from selenium.webdriver.common.by import By


def crawl(url, max_urls=30):
    """
    Crawls a web page and extracts all links.
    You'll find all links in `external_urls` and `internal_urls` global set variables.
    params:
        max_urls (int): number of max urls to crawl, default is 30.
    """
    global last_url
    global total_urls_visited
    internal_urls.add(url)
    parse_url(url)
    while len(to_parse_urls):
        print(f"{GREEN}[*] {total_urls_visited}/{max_urls}")
        print(f"{GRAY}[*] In bag parse: {len(to_parse_urls)}")
        next_url = take_next()
        if total_urls_visited >= max_urls or not next_url:
            break
        parse_url(next_url)
        total_urls_visited += 1


def take_next():
    """
    Get an URL from the least used cluster or unclustered
    """
    global to_parse_urls
    global internal_urls
    global parsed_clusters
    global force_urls

    if len(force_urls):
        return force_urls.pop()

    url_clusters = urlclustering.cluster(list(internal_urls), 15)
    url_count = {}
    url_cluster = {}
    has_unclustered = False
    unclustered = []
    for url in to_parse_urls:
        for ref, urls in url_clusters['clusters'].items():
            if url in urls:
                if ref not in parsed_clusters:
                    parsed_clusters[ref] = 0
                if parsed_clusters[ref] <= 8:
                    url_count[url] = parsed_clusters[ref]
                    url_cluster[url] = ref
        if url in url_clusters['unclustered']:
            has_unclustered = True
            unclustered.append(url)
            #url_count[url] = parsed_clusters['unclustered']
            #url_cluster[url] = 'unclustered'
    #import ipdb; ipdb.set_trace()

    if len(url_count) == 0 and not has_unclustered:
        return False

    # compare the number of clusters vs the number of unclustered urls and get a prob
    prob_unclusters = len(unclustered) / \
        (len(url_clusters['clusters']) + len(unclustered))
    print(len(unclustered), len(url_clusters['clusters']), prob_unclusters)
    if (has_unclustered and random.random() < prob_unclusters) or (has_unclustered and len(url_count) == 0):
        # prob% of the time take from unclustered
        less_url = random.choice(unclustered)
        less_cluster = 'unclustered'
    else:
        less_url = min(url_count, key=url_count.get)
        less_cluster = url_cluster[less_url]
    print("CLUSTER", less_cluster, parsed_clusters[less_cluster])

    #print(less_cluster, less_url)

    parsed_clusters[less_cluster] += 1
    to_parse_urls.remove(less_url)
    # print(parsed_clusters)
    return less_url


def login(url, username, password, username_element, password_element, login_element, ss_path):
    """
    Login
    """
    global request_session
    print(f"{GREEN}[*] LOGIN")
    # Use 'with' to ensure the session context is closed after use.
    driver.get(url)
    username_box = driver.find_element_by_css_selector(username_element)
    username_box.send_keys(username)
    time.sleep(0.2)
    password_box = driver.find_element_by_css_selector(password_element)
    password_box.send_keys(password)
    time.sleep(0.2)
    login_box = driver.find_element_by_css_selector(login_element)
    login_box.click()
    time.sleep(5)
    driver.save_screenshot(ss_path)
    cookies = driver.get_cookies()
    # This returns cookie dictionaries for your session.
    # Next, set those cookies in requests:
    for cookie in cookies:
        request_session.cookies.set(cookie['name'], cookie['value'])
    internal_urls.add(url)
    parse_url(url)


def url2file(url):
    parsed = urlparse(url)
    file = f"{parsed.netloc}{parsed.path}{parsed.params}{parsed.query}{parsed.fragment}"
    return file.replace("/", "_")


def is_valid(url):
    """
    Checks whether `url` is a valid URL.
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme) and not parsed.scheme == 'data'


def save_css(url, filename):
    global request_session
    content = request_session.get(url).content
    path = f"runs/{execution_uuid}/css/{filename}"
    minified = css_minify(content.decode("utf-8"), comments=False)
    with open(path, "w") as f:
        print(minified, file=f)
    return os.path.getsize(path)


def save_js(url, filename):
    content = requests.get(url).content
    with open(f"runs/{execution_uuid}/js/{filename}", "w") as f:
        print(content.decode("utf-8"), file=f)


def is_resource(url):
    invalids = ["jpg", "png", "jpeg", "webp", "gif", "eps", "tiff", "pdf"]
    invalids += ["psd", "ai", "raw", "ico", "bmp", "svg", "apng"]
    invalids += ["mpeg", "mp4", "avif", "mp3"]
    if url[-2:].lower() in invalids and url[-3] == ".":
        return True
    if url[-3:].lower() in invalids and url[-4] == ".":
        return True
    if url[-4:].lower() in invalids and url[-5] == ".":
        return True
    return False


def is_downloadable(request):
    """
    Does the url contain a downloadable resource
    """
    header = request.headers
    content_type = header.get('content-type')
    if 'text' in content_type.lower():
        return True
    if 'html' in content_type.lower():
        return True
    return False


def parse_css(soup):
    # find all css files in the current link
    css = soup.findAll('link', href=True, type='text/css')
    css += soup.findAll('link', href=True, rel='stylesheet')
    for styletag in css:
        # if not styletag.string: # probably an external sheet
        #    continue
        # cssutils.parseStyle(styletag.string))
        href = styletag['href']
        if not href:
            continue
        href = urljoin(url, href)
        #parsed_href = urlparse(href)
        # remove URL GET parameters, URL fragments, etc.
        #href_ = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if not is_valid(href):
            # not a valid URL
            continue
        # print(href)
        if not href in css_files:
            filename = str(uuid.uuid4())
            filename = f"{filename}.css"
            file_size = save_css(href, filename)
            css_files[href] = (filename, file_size)


def parse_js(soup):
    # find all js files in the current link
    js = soup.findAll('script', src=True)
    for script in js:
        href = script['src']
        if not href:
            continue
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        # remove URL GET parameters, URL fragments, etc.
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if not is_valid(href):
            # not a valid URL
            continue
        if not href in js_files:
            filename = str(uuid.uuid4())
            filename = f"{filename}.js"
            js_files[href] = filename
            save_js(href, filename)


def parse_links(soup):
    urls = set()
    domain_name = urlparse(url).netloc
    for a_tag in soup.findAll("a"):

        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            # href empty tag
            continue
        if is_resource(href):
            continue
        # join the URL if it's relative (not absolute link)
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        # remove URL GET parameters, URL fragments, etc.
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        href = href.strip()
        if href[-1] != '/':
            href = f"{href}/"
        if not is_valid(href):
            # not a valid URL
            continue
        if href in internal_urls:
            # already in the set
            continue
        if domain_name not in href:
            # external link
            if href not in external_urls:
                #print(f"{GRAY}[!] External link: {href}{RESET}")
                external_urls.add(href)
            continue
        #print(f"{GREEN}[*] Internal link: {href}{RESET}")
        urls.add(href)
        internal_urls.add(href)
    return urls


def read_html(url):
    global request_session
    # all URLs of `url`
    url = url.strip()
    if is_resource(url):
        return False
    print(f"{YELLOW}[*] Crawling: {url}{RESET}")

    # using requests
    #request = request_session.get(url)
    # if not is_downloadable(request):
    #    return False
    #content = request.content

    # using selenium
    driver.get(url)

    #content = driver.page_source
    content = driver.find_element(By.TAG_NAME, "html").get_attribute('innerHTML')

    uuid_ = str(uuid.uuid4())
    filename = f"{uuid_}.html"

    #ss_path = f"runs/{execution_uuid}/ss/{uuid_}.png"
    # driver.save_screenshot(ss_path)

    with open(f"runs/{execution_uuid}/html/{filename}.html", "w") as f:
        try:
            print(content, file=f)
        except UnicodeDecodeError as e:
            print(f"{RED}[*]e")
            return False
        parsed_urls[url] = filename
    soup = BeautifulSoup(content, "html.parser")
    return soup


def parse_url(url):
    global to_parse_urls
    """
    Returns all URLs that is found on `url` in which it belongs to the same website
    """
    soup = read_html(url)
    if not soup:
        return set()
    parse_css(soup)
    parse_js(soup)
    links = parse_links(soup)
    to_parse_urls = to_parse_urls.union(links)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Link Extractor Tool with Python")
    parser.add_argument("-u", "--url", help="The URL to extract links from.")
    parser.add_argument("--uuid", help="Execution UUID")
    parser.add_argument("--chrome", help="Chrome driver path", default='chromedriver_linux64/chromedriver')
    parser.add_argument(
        "-m", "--max-urls", help="Number of max URLs to crawl, default is 30.", default=30, type=int)

    parser.add_argument("--login_url", default=False,
                        help="Optional. If the login URL differs from the main parse URL")
    parser.add_argument("--login_btn_selector", default=False)
    parser.add_argument("--username", default=False)
    parser.add_argument("--username_selector", default=False)
    parser.add_argument("--password", default=False)
    parser.add_argument("--password_selector", default=False)
    parser.add_argument("--extra_urls", nargs="+", default=[])

    args = parser.parse_args()

    # initialize chrome driver
    options = Options()
    options.add_argument("--disable-dev-shm-usage")
    #options.add_argument("--headless")
    # options.add_argument("start-maximized")
    # options.add_argument('--no-sandbox')
    options.add_argument("--disable-notifications")
    # options.add_argument("--remote-debugging-port=9225")
    driver = webdriver.Chrome(args.chrome, options=options)

    # init the colorama module
    colorama.init()

    GREEN = colorama.Fore.GREEN
    GRAY = colorama.Fore.LIGHTBLACK_EX
    RESET = colorama.Fore.RESET
    YELLOW = colorama.Fore.YELLOW
    RED = colorama.Fore.RED

    # initialize the set of links (unique links)
    internal_urls = set()
    parsed_urls = {}
    external_urls = set()
    css_files = {}
    js_files = {}
    parsed_domain_name = ""
    parsed_clusters = {
        'unclustered': 0
    }
    total_urls_visited = 0
    to_parse_urls = set()
    force_urls = set()
    execution_uuid = args.uuid

    if not execution_uuid:
        import uuid
        execution_uuid = str(uuid.uuid4())
    request_session = requests.Session()

    if args.extra_urls:
        for extra_url in args.extra_urls:
            # todo is this url ok?
            force_urls.add(extra_url)

    print(f"{YELLOW}[*] Execution: {execution_uuid}")

    os.makedirs(f"runs/{execution_uuid}")
    os.makedirs(f"runs/{execution_uuid}/html")
    os.makedirs(f"runs/{execution_uuid}/css")
    os.makedirs(f"runs/{execution_uuid}/js")
    os.makedirs(f"runs/{execution_uuid}/cssout")
    os.makedirs(f"runs/{execution_uuid}/reports")
    os.makedirs(f"runs/{execution_uuid}/ss")

    url = args.url
    last_url = url
    max_urls = args.max_urls
    if args.username:
        login_url = args.login_url if args.login_url else url
        ss_path = f"runs/{execution_uuid}/reports/login.png"
        login(login_url, args.username, args.password, args.username_selector,
              args.password_selector, args.login_btn_selector, ss_path)
    crawl(url, max_urls=max_urls)

    print("[+] Total Internal links:", len(internal_urls))
    print("[+] Total External links:", len(external_urls))
    print("[+] Total CSS files:", len(css_files))
    print("[+] Total JS files:", len(js_files))
    print("[+] Total URLs:", len(external_urls) + len(internal_urls))
    print("[+] Total crawled URLs:", len(parsed_urls))

    domain_name = urlparse(url).netloc

    # save the internal links to a file
    with open(f"runs/{execution_uuid}/reports/internal_links.txt", "w") as f:
        for internal_link in internal_urls:
            print(internal_link.strip(), file=f)

    # save the internal links to a file
    with open(f"runs/{execution_uuid}/reports/parsed_links.txt", "w") as f:
        for url, filename in parsed_urls.items():
            url = url.strip()
            print(f"{url},{filename}", file=f)

    # save the external links to a file
    with open(f"runs/{execution_uuid}/reports/external_links.txt", "w") as f:
        for external_link in external_urls:
            print(external_link.strip(), file=f)

    # save the js files to a file
    with open(f"runs/{execution_uuid}/reports/parsed_clusters.txt", "w") as f:
        print(f"{parsed_clusters}", file=f)

    # save the js files to a file
    with open(f"runs/{execution_uuid}/reports/js.txt", "w") as f:
        for js_file, filename in js_files.items():
            js_file = js_file.strip()
            print(f"{js_file},{filename}", file=f)

    # save the css files to json report file
    elements = []

    # save the css files to a file
    with open(f"runs/{execution_uuid}/reports/css.txt", "w") as f:
        for css_file, filename_size in css_files.items():
            filename, file_size = filename_size
            css_file = css_file.strip()
            # save the result
            original_path = f"runs/{execution_uuid}/css/{filename}"
            cmds = ["purgecss", "--css", original_path,
                    "--content", f"runs/{execution_uuid}/html/*"]
            with open(original_path, "r") as reader:
                original_file = reader.read()
            res = check_output(cmds, stderr=STDOUT)
            new_size = 0
            try:
                res_json = json.loads(res.decode("utf-8"))
                minified = css_minify(
                    res_json[0]['css'].strip(), comments=False)
                path = f"runs/{execution_uuid}/cssout/{filename}"
                with open(path, "w") as f2:
                    print(minified, file=f2)
                new_size = os.path.getsize(path)
            except json.decoder.JSONDecodeError as e:
                with open(f"runs/{execution_uuid}/reports/css_error.txt", "w") as f3:
                    print(css_file, file=f3)
            #original_file, new_file
            res = {}
            res['css_file'] = css_file
            # only filename ej style.css
            parsed = urlparse(css_file)
            file_name = os.path.basename(parsed.path)
            res['file_name'] = file_name
            res['uuid'] = filename
            res['original_size'] = file_size
            res['new_size'] = new_size
            elements.append(res)
            print(f"{css_file},{filename},{file_size},{new_size}", file=f)
    json_report = {}
    json_report['css'] = elements
    json_report['css_count'] = len(elements)
    with open(f"runs/{execution_uuid}/reports/json_css.json", "w") as f:
        print(f"{json.dumps(json_report)}", file=f)
    print("Execution UUID", execution_uuid)
