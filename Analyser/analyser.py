import json
import re
import socket
import ssl
import string
import urllib.parse
from urllib.error import URLError
from urllib.parse import urlparse
import idna
import numpy as np
import requests
from bs4 import BeautifulSoup
from dgaintel import get_prob
import dns.resolver
from ipwhois import IPWhois
from Wappalyzer import Wappalyzer, WebPage
import whois
import datetime
import geoip2.database
from pysafebrowsing import SafeBrowsing
from googlesearch import search
from jarm.scanner.scanner import Scanner

from WebsiteSecurityAnalyser import settings

geoip2_reader = geoip2.database.Reader('GeoLite2-Country.mmdb')


def compare_with_google(url, api):
    s = SafeBrowsing(api)
    urls = []
    urls.append(url)
    r = s.lookup_urls(urls)
    return r


def get_ip(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(':')[0]
    if domain:
        ip_address = socket.gethostbyname(domain)
    else:
        ip_address = socket.gethostbyname(url)
    return ip_address


def get_dns_records(domain, record_type, raw=False):
    """
    Gets DNS records for a domain of a given record type.

    Args:
    - domain (str): The domain to look up.
    - record_type (str): The type of DNS record to look up (e.g. 'A', 'MX', 'CNAME', 'TXT', etc.).

    Returns:
    - A list of strings representing the DNS records for the given domain and record type.
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        if raw:
            return answers
        return [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        print(f"No {record_type} record found for {domain}")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"{domain} does not exist")
        return []
    except Exception as e:
        print(f"Error occurred while looking up {record_type} record for {domain}: {e}")
        return []


def check_if_has_ssl(url):
    # Check if the website has a valid SSL certificate and is using HTTPS
    """
    Check if the URL uses the HTTPS protocol and validate the SSL/TLS certificate.
    """
    try:
        # Check if the URL uses the HTTPS protocol
        if not url.startswith("https://"):
            print("Error: URL does not use the HTTPS protocol.")
            return False

        # Validate the SSL/TLS certificate
        context = ssl.create_default_context()
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.split(':')[0]
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_hostname = cert["subjectAltName"][0][1]
                if cert_hostname != url.split("//")[1].split("/")[0]:
                    print("Error: Certificate does not match the domain name.")
                    return False, None
                else:
                    return True, cert
    except URLError as e:
        print("Error: " + str(e))
        return False, None


class Analyser:
    def __init__(self, url, virus_total_token, google_safe_browsing_key):
        self.virus_total_token = virus_total_token
        self.google_safe_browsing_key = google_safe_browsing_key

        self.url = url
        # Make a GET request to the URL
        self.response = requests.get(self.url, timeout=3, allow_redirects=True)

        # Parse the HTML content of the response using BeautifulSoup
        self.soup = BeautifulSoup(self.response.content, 'html.parser')
        try:
            self.google_safe_browsing = compare_with_google(self.url, self.google_safe_browsing_key)
        except:
            self.google_safe_browsing = {url: {"malicious": False}}

        self.ssl_cert = check_if_has_ssl(url)

        try:
            self.whois = whois.whois(self.url)
        except:
            self.whois = None

        try:
            self.ip_address = get_ip(url)
        except:
            self.ip_address = None

        self.wappalyzer = Wappalyzer.latest()

    # Basic summery
    def is_suspicious_length(self, length: int) -> bool:
        parsed = urllib.parse.urlparse(self.url)
        if len(parsed.netloc) > length or len(parsed.path) > length:
            return True
        return False

    def get_dga_score(self) -> float:
        prob = get_prob(self.url, raw=True)
        return float(prob)

    def detect_at_symbol(self) -> bool:
        if '@' in self.url:
            return True
        else:
            return False

    def detect_multiple_http(self) -> bool:
        if re.search(r'^https?:\/\/(https?:\/\/)+', self.url):
            return True
        else:
            return False

    def detect_punycode(self) -> bool:
        try:
            decoded_url = idna.decode(self.url)
            if decoded_url != self.url:
                return True
            else:
                return False
        except idna.IDNAError:
            return False

    def is_url_with_ip(self):
        # Regular expression pattern to match IP address
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

        # Extract hostname from URL
        hostname = re.findall(r"https?://([^/:]+)", self.url)[0]

        # Check if hostname is an IP address
        if re.match(ip_pattern, hostname):
            return True
        else:
            return False

    def get_summery(self):
        return {"URL with IP": self.is_url_with_ip(), "Suspicious Length": self.is_suspicious_length(50),
                "DGA Score": self.get_dga_score(), "URL with @": self.detect_at_symbol(),
                "URL with Multiple http": self.detect_multiple_http(), "URL with PunyCode": self.detect_punycode()}

    # html related
    def find_hidden_elements(self):
        try:
            if self.response.status_code == 200:
                hidden_elements = []
                for element in self.soup.find_all('input', type='hidden'):
                    hidden_elements.append(element)
                return {"count": len(hidden_elements), "elements": hidden_elements}
            else:
                return {"count": 0, "elements": []}
        except:
            return {"count": 0, "elements": []}

    def find_hidden_iframes(self):
        try:
            if self.response.status_code == 200:
                hidden_iframes = []
                for element in self.soup.find_all('iframe', style='display:none;'):
                    hidden_iframes.append(element)
                return {"count": len(hidden_iframes), "elements": hidden_iframes}
            else:
                return {"count": 0, "elements": []}
        except:
            return {"count": 0, "elements": []}

    def find_iframes(self):
        try:
            if self.response.status_code == 200:
                hidden_iframes = []
                for element in self.soup.find_all('iframe'):
                    hidden_iframes.append(element)
                return {"count": len(hidden_iframes), "elements": hidden_iframes}
            else:
                return {"count": 0, "elements": []}
        except:
            return {"count": 0, "elements": []}

    def get_javascript_variables(self, html_content=None):
        # Extract the HTML content from the response
        if not html_content:
            html_content = self.response.text

        # Search for JavaScript variables in the HTML content using regular expressions
        js_variables = re.findall(r'var\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=', html_content)

        # Return the JavaScript variables
        return js_variables

    def find_obfuscated_scripts(self, threshold=0.30):
        try:
            js_variables = [self.get_javascript_variables()]
            if self.response.status_code == 200:
                scripts = []
                all_scripts = []
                for element in self.soup.find_all('script'):
                    if 'javascript' in element.attrs.get('type', '').lower() and \
                            re.search(r'\\x[0-9a-fA-F]{2}', str(element), re.IGNORECASE):
                        scripts.append(element)

                script_tags = self.soup.find_all("script", src=True)

                # Check each script tag for obfuscation
                for tag in script_tags:
                    # Find any URLs referenced in the script
                    url = tag["src"]
                    all_scripts.append(url)
                    # Open the URL and fetch the script content
                    script_res = requests.get(url)
                    script_content = script_res.text
                    js_variables.append(self.get_javascript_variables(script_content))
                    # If the percentage of non-alphanumeric characters exceeds the threshold, consider it obfuscated
                    pattern = r"/\*![^*]*\*+([^/][^*]*\*+)*/"
                    if re.search(pattern, script_content):
                        non_alphanumeric_count = sum(1 for c in script_content if c not in string.ascii_letters
                                                     and c not in string.digits)
                        total_count = len(script_content)
                        non_alphanumeric_ratio = non_alphanumeric_count / total_count
                        # If the percentage of non-alphanumeric characters exceeds the threshold, consider it obfuscated
                        if non_alphanumeric_ratio >= threshold:
                            scripts.append({"url": url})
                return {"count": len(scripts), "elements": scripts, "all_scripts": all_scripts,
                        "js_variables": js_variables}
            else:
                return {"count": 0, "elements": []}
        except:
            return {"count": 0, "elements": []}

    def find_suspicious_html_elements(self):
        try:
            if self.response.status_code == 200:
                suspicious_elements = []
                for element in self.soup.find_all():
                    if element.name in ['input', 'textarea', 'select']:
                        if element.attrs.get('type') in ['text', 'password', 'email']:
                            suspicious_elements.append(element)
                    elif element.name == 'img':
                        if element.attrs.get('src', '').startswith('data:'):
                            suspicious_elements.append(element)

                # Look for suspicious script tags
                script_tags = self.soup.find_all('script')
                for tag in script_tags:
                    if 'eval(' in str(tag) or 'document.write' in str(tag):
                        suspicious_elements.append(tag)

                # Look for suspicious iframe tags
                iframe_tags = self.soup.find_all('iframe')
                for tag in iframe_tags:
                    if 'srcdoc' in tag.attrs or 'sandbox' not in tag.attrs:
                        suspicious_elements.append(tag)

                # Look for suspicious form tags
                form_tags = self.soup.find_all('form')
                for tag in form_tags:
                    if 'action' in tag.attrs and 'login' in tag.attrs['action']:
                        suspicious_elements.append(tag)

                # Look for suspicious meta tags
                meta_tags = self.soup.find_all('meta')
                for tag in meta_tags:
                    if 'http-equiv' in tag.attrs and tag.attrs['http-equiv'].lower() == 'refresh':
                        suspicious_elements.append(tag)

                # Look for suspicious link tags
                link_tags = self.soup.find_all('link')
                for tag in link_tags:
                    if 'href' in tag.attrs and 'javascript:' in tag.attrs['href']:
                        suspicious_elements.append(tag)

                # Return the list of suspicious elements
                return {"count": len(suspicious_elements), "elements": suspicious_elements}
            else:
                return {"count": 0, "elements": []}
        except:
            return {"count": 0, "elements": []}

    def count_suspicious_programs(self):
        try:
            # Get the HTML content of the webpage
            html = self.response.content.decode('utf-8')

            # Define regular expressions to match suspicious patterns
            pattern1 = r"<script.*?>\s*eval\s*\("
            pattern2 = r"document\.write\s*\("
            pattern3 = r"setTimeout\s*\("
            pattern4 = r"setInterval\s*\("
            pattern5 = r"exec\s*\("
            pattern6 = r"shell\s*\("
            pattern7 = r"cmd\s*\("
            pattern8 = r"wget\s*\("
            pattern9 = r"curl\s*\("
            pattern10 = r"python\s*\("
            pattern11 = r"php\s*\("

            # Compile the regular expressions into pattern objects
            patterns = [re.compile(p) for p in
                        [pattern1, pattern2, pattern3, pattern4, pattern5, pattern6, pattern7, pattern8, pattern9,
                         pattern10, pattern11]]

            # Count the number of matches for each pattern in the HTML content
            counts = [len(p.findall(html)) for p in patterns]

            # Return the total count of suspicious programs found
            return sum(counts), [p.findall(html) for p in patterns]

        except:
            print("Error: Could not retrieve content from URL")
            return {"count": 0, "elements": []}

    def detect_button_trap(self):
        # Download the HTML code for the webpage
        html = self.response.text

        # Define regular expressions to match suspicious patterns
        pattern1 = r"<a.*?\bstyle\s*=\s*['\"]display\s*:\s*none;.*?>"
        pattern2 = r"<button.*?\bstyle\s*=\s*['\"]display\s*:\s*none;.*?>"
        pattern3 = r"<input.*?\btype\s*=\s*['\"]hidden['\"].*?>"

        # Search for the patterns in the HTML code
        match1 = re.search(pattern1, html)
        match2 = re.search(pattern2, html)
        match3 = re.search(pattern3, html)

        # Assign a danger rating based on the number of matches found
        danger_rating = 0
        if match1:
            danger_rating += 1
        if match2:
            danger_rating += 2
        if match3:
            danger_rating += 3

        # Return the danger rating
        if danger_rating == 0:
            return {"rating": "Normal", "danger_rating": danger_rating}
        elif danger_rating <= 2:
            return {"rating": "Medium", "danger_rating": danger_rating}
        else:
            return {"rating": "Dangerous", "danger_rating": danger_rating}

    def check_credential_form(self):
        """
        Checks if a credential input form is safe or dangerous.

        Args:
            url (str): The URL of the web page containing the credential input form.

        Returns:
            str: 'safe' if the form is safe, 'dangerous' otherwise.
        """
        # Find the credential input form on the page
        form = self.soup.find('form', {'method': 'post', 'enctype': 'multipart/form-data'})

        # Check if the form exists
        if form is None:
            return 'safe'

        # Check if the form is served over HTTPS
        if not self.url.startswith('https'):
            return 'dangerous'

        # Check if the form has client-side validation in place
        if not form.has_attr('onsubmit'):
            return 'dangerous'

        # Check if the input fields are labeled correctly
        for input_field in form.find_all('input'):
            if input_field.get('type') == 'password' and not input_field.has_attr('autocomplete'):
                return 'dangerous'

        # Check if the action URL of the form belongs to the same domain as the page
        action_url = form.get('action')
        if not action_url.startswith(self.url):
            return 'dangerous'

        # If all checks pass, the form is safe
        return 'safe'

    def check_suspicious_submit_events(self):
        # Make a GET request to the URL

        # Find all form elements on the page
        forms = self.soup.find_all('form')

        # Iterate over all form elements
        for form in forms:
            # Check if the form has a submit event handler function
            if form.has_attr('onsubmit'):
                # Get the submit event handler function
                onsubmit = form['onsubmit']

                # Define regular expressions to match suspicious patterns
                pattern1 = r"<script.*?>\s*eval\s*\("
                pattern2 = r"document\.write\s*\("
                pattern3 = r"setTimeout\s*\("
                pattern4 = r"setInterval\s*\("
                pattern5 = r"exec\s*\("
                pattern6 = r"shell\s*\("
                pattern7 = r"cmd\s*\("
                pattern8 = r"wget\s*\("
                pattern9 = r"curl\s*\("
                pattern10 = r"python\s*\("
                pattern11 = r"php\s*\("

                # Check if any suspicious pattern matches the event handler function
                if (re.search(pattern1, onsubmit, re.IGNORECASE) or
                        re.search(pattern2, onsubmit, re.IGNORECASE) or
                        re.search(pattern3, onsubmit, re.IGNORECASE) or
                        re.search(pattern4, onsubmit, re.IGNORECASE) or
                        re.search(pattern5, onsubmit, re.IGNORECASE) or
                        re.search(pattern6, onsubmit, re.IGNORECASE) or
                        re.search(pattern7, onsubmit, re.IGNORECASE) or
                        re.search(pattern8, onsubmit, re.IGNORECASE) or
                        re.search(pattern9, onsubmit, re.IGNORECASE) or
                        re.search(pattern10, onsubmit, re.IGNORECASE) or
                        re.search(pattern11, onsubmit, re.IGNORECASE)):
                    return "Dangerous"

        # If no suspicious submit events were found, return "Safe"
        return "Safe"

    def extract_favicon_url(self):
        """
        Extracts the URL of a website's favicon.
        """

        # Find the website's favicon.
        favicon_link = self.soup.find('link', rel='shortcut icon') or self.soup.find('link', rel='icon')

        # Return the URL of the website's favicon.
        if favicon_link:
            return favicon_link['href']
        else:
            return None

    def check_fake_favicon(self):
        try:
            # Make an HTTP GET request to the URL of the webpage

            # Extract the favicon URL from the HTML of the webpage
            favicon_url = self.extract_favicon_url()

            # Make an HTTP GET request to the favicon URL
            response = requests.get(favicon_url)

            # Check if the HTTP response code is 200 (OK) or not
            if response.status_code != 200:
                return "Dangerous"
            else:
                content_type = response.headers.get("content-type")
                if content_type in ["image/x-icon", "image/vnd.microsoft.icon"]:
                    return "Safe"
                else:
                    return "Dangerous"
        except:
            return "Error"

    def get_html_analysis(self):
        return {"Hidden Element": self.find_hidden_elements(), "Hidden Iframe": self.find_hidden_iframes(),
                "Iframe": self.find_iframes(), "Obfuscated Script": self.find_obfuscated_scripts(),
                "Suspicious HTML Element": self.find_suspicious_html_elements(),
                "Suspicious Program": self.count_suspicious_programs(), "Button Trap": self.detect_button_trap(),
                "Credential Input Form": self.check_credential_form(),
                "Form Event": self.check_suspicious_submit_events(),
                "Fake Favicon": self.check_fake_favicon()
                }

    def check_domain_safety(self):
        domain = self.url
        check_domains = [
            ['Google', 'https://transparencyreport.google.com/safe-browsing/search?url=' + domain],
            ['Yandex', 'https://yandex.com/safety/?url=' + domain],
            ['McAfee', 'https://www.siteadvisor.com/sitereport.html?url=' + domain],
            ['Securi', 'https://labs.sucuri.net/blacklist/info/?domain=' + domain],
            ['VirusTotal', 'https://www.virustotal.com/gui/domain/' + domain + '/detection'],
            ['Green Snow', 'https://greensnow.co/view/' + domain],
            ['Spam Rats', 'https://www.spamrats.com/lookup.php?ip=' + domain],
            ['Is it hacked?', 'https://isithacked.com/check/' + domain],
        ]

        for name, url in check_domains:
            # take_screenshot(url, name+'_website.png')
            response = requests.get(url)
            if response.status_code == 200:
                print(f"{name}: Safe")
            else:
                print(f"{name}: Potentially Dangerous")

    def is_fake_domain(self):
        # Check if the domain name matches a known fake domain pattern
        fake_domain_patterns = ['fake', 'phishing', 'scam', 'spam', 'hack', 'malware', 'virus', 'fraud', 'attack']
        for pattern in fake_domain_patterns:
            if pattern in self.url:
                return True, "matches fake pattern"

        # Check if the domain name has a short lifespan
        try:
            whois_info = self.whois
            if isinstance(whois_info.expiration_date, list):
                expiration_date = whois_info.expiration_date[0]
            else:
                expiration_date = whois_info.expiration_date
            days_until_expire = (expiration_date - datetime.datetime.now()).days
            if days_until_expire <= 90:
                return True, "expires in 90days"
        except:
            pass

        # Check if the website is listed as a known malware or phishing site
        try:
            if self.google_safe_browsing[self.url]["malicious"]:
                return True, self.google_safe_browsing
        except Exception as e:
            print(e)
            pass

        return False

    def find_domain_location(self, ip=None):
        # Get the IP address for the domain
        if not ip:
            ip = self.ip_address

        try:
            response = geoip2_reader.country(ip)
            return response.country.name
        except:
            url = "https://ipinfo.io/" + ip + "/json"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                return data.get("city") + "-" + data.get("region") + "-" + data.get("country")
            else:
                return ""

    def is_newborn_domain(self):
        # Get WHOIS data for the URL
        domain_info = self.whois

        # Check if the domain was created less than a month ago
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date
        days_since_creation = (datetime.datetime.now() - creation_date).days
        if days_since_creation < 30:
            return True
        else:
            return False

    def check_abuse_record(self):
        # Defining the api-endpoint
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': self.ip_address,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': '6042666ef6437d90aa19c1715292e9ee89d7ada55936e8fe256ce7a9b8b4eae601a852a9030a362e'
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        if response.status_code != 200:
            return f'Error {response.status_code}: {response.text}'

        data = json.loads(response.text)
        return data

    def check_phishing(self):
        return self.google_safe_browsing

    def has_mail_server(self):
        parsed_url = urlparse(self.url)
        domain = parsed_url.netloc.split(':')[0]
        mx_records = get_dns_records(domain, 'MX', raw=True)
        mail_servers = [(str(mx_record.exchange).rstrip('.'), mx_record.preference) for mx_record in mx_records]
        # Sort the mail servers by their preference value
        mail_servers.sort(key=lambda x: x[1])
        # Return the list of mail servers
        return mail_servers

    def has_spf_record(self):
        parsed_url = urlparse(self.url)
        domain = parsed_url.netloc.split(':')[0]
        # Query the TXT record for the SPF policy
        answers = get_dns_records(domain, 'TXT', raw=True)
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode('utf-8').startswith('v=spf1'):
                    # Found an SPF record
                    return {"is_spf": True, "text_records": txt_string}
        # No SPF record found
        return {"is_spf": False, "text_records": None}

    def get_dns_records(self):
        answers = []
        parsed_url = urlparse(self.url)
        domain = parsed_url.netloc.split(':')[0]
        # Query the TXT record
        answers.append(get_dns_records(domain, 'TXT'))
        answers.append(get_dns_records(domain, 'SOA'))
        answers.append(get_dns_records(domain, 'NS'))
        answers.append(get_dns_records(domain, 'MX'))
        return answers

    def get_site_reputation(self):
        endpoint = 'https://www.virustotal.com/api/v3/urls/'
        headers = {'x-apikey': self.virus_total_token}
        params = {'url': self.url}
        response = requests.get(endpoint, headers=headers, params=params)
        if response.status_code == 200:
            json_response = response.json()
            data = json_response['data']
            attributes = data['attributes']
            categories = attributes.get('categories', {})
            reputation = categories.get('malicious', None)
            return reputation
        else:
            return None

    def get_common_analysis(self):
        return {
            "Fake Domain": self.is_fake_domain(), "SSL": self.ssl_cert,
            "Locations": self.find_domain_location(), "Newborn Domain": self.is_newborn_domain(),
            "Abuse Record": self.check_abuse_record(), "Phishing Record": self.check_phishing(),
            "Mail Server": self.has_mail_server(), "Spam (SPF1 Result)": self.has_spf_record(),
            "Site Reputation": self.get_site_reputation()
        }

    def get_technologies(self):
        # Initialize the Wappalyzer object
        webpage = WebPage.new_from_url(self.url)
        technologies = self.wappalyzer.analyze_with_versions_and_categories(webpage)

        return technologies

    def find_redirection_to_another_as_country(self, ip=None, url=None, response_p=None):
        if ip:
            # Get the IP address of the URL
            ip_address = ip

            # Get the AS number of the URL
            url_asn = whois.whois(ip_address).asn
            url_country = self.find_domain_location(ip_address)
            # Send a GET request to the URL
            if response_p:
                response = response_p
            else:
                if url:
                    response = requests.get(url, allow_redirects=True)
                else:
                    response = requests.get(ip, allow_redirects=True)
        else:
            url_asn = self.whois.asn
            response = self.response
            url_country = self.find_domain_location()

        # Find all redirections in the response headers
        redirections = []
        countries = []
        for redirect in response.history:
            # Get the IP address of the redirected URL
            redirect_ip_address = get_ip(redirect.url)

            # Get the AS number of the redirected URL
            redirect_asn = whois.whois(redirect_ip_address).asn
            redirect_c = self.find_domain_location(redirect_ip_address)
            # Check if the AS numbers are different
            if url_asn != redirect_asn:
                redirections.append({'url': redirect.url, 'redirect_asn': redirect_asn,
                                     'ip': redirect_ip_address})
            if url_country != redirect_c:
                countries.append({'url': redirect.url, 'redirect_c': redirect_c,
                                  'ip': redirect_ip_address})

        return {'redirect_asn': redirections, 'countries': countries}

    def get_links_and_ips(self):
        # Get all the links present on the webpage
        links = []
        for link in self.soup.find_all('a'):
            if link.get('href') not in links and link.get('href') != "#" and 'mailto' not in link.get('href'):
                links.append(link.get('href'))
        # Get all the IP addresses present on the webpage
        link_details = []
        for link in links:
            parsed_url = urlparse(link)
            host = parsed_url.netloc.split(':')[0]
            exist_host = None
            for item in link_details:
                if item['host'] == host:
                    exist_host = item
                    break
            if not exist_host:
                try:
                    ip_address = get_ip(link)
                except Exception as e:
                    print(e)
                    ip_address = None
                location = None
                url_asn = None
                as_number = None
                if ip_address:
                    location = self.find_domain_location(ip=ip_address)
                    try:
                        ipwhois = IPWhois(ip_address)
                        results = ipwhois.lookup_rdap()
                        as_number = results["asn"]
                        url_asn = results["asn_description"]
                    except Exception as e:
                        print(e)
                link_details.append({"host": host, "link": link, "ip": ip_address, "location": location,
                                     "as_name": url_asn, "as_number": as_number})
            else:
                exist_host["link"] = link
                link_details.append(exist_host)
        # Return the links and IPs as a tuple
        return link_details

    def find_suspicious_cookies(self):
        # Extract the cookies from the response
        cookies = self.response.cookies

        # Initialize an empty list to store suspicious cookies
        suspicious_cookies = []

        # Iterate over the cookies
        for cookie in cookies:
            # Check if the cookie is an HTTP-only cookie
            if cookie.get('httponly', False):
                suspicious_cookies.append(cookie)

            # Check if the cookie has a secure flag but the request was made over HTTP
            if cookie.get('secure', False) and not self.response.url.startswith('https'):
                suspicious_cookies.append(cookie)

            # Check if the cookie has an expiration date set far in the future
            if cookie.get('expires', False):
                # Convert the expiration date to a datetime object
                expiration_date = datetime.datetime.strptime(cookie['expires'], '%a, %d-%b-%Y %H:%M:%S %Z')

                # Calculate the number of days until the cookie expires
                days_until_expiration = (expiration_date - datetime.datetime.now()).days

                # Check if the cookie expires more than a year in the future
                if days_until_expiration > 365:
                    suspicious_cookies.append(cookie)

        return suspicious_cookies

    def get_website_title(self):
        # Find the title tag and extract its text
        title_tag = self.soup.find('title')
        if title_tag is not None:
            return title_tag.text.strip()
        else:
            return None

    def get_jarm_hash(self):
        parsed_url = urlparse(self.url)
        domain = parsed_url.netloc.split(':')[0]
        # Compute the JARM hash
        jarm_data = Scanner.scan(domain, 443)
        return jarm_data

    def get_technology_and_dns_analysis(self):
        return {
            'technologies': self.get_technologies(),
            'redirection_to_another_as_country': self.find_redirection_to_another_as_country(),
            'links_and_ips': self.get_links_and_ips(), 'suspicious_cookies': self.find_suspicious_cookies(),
            'website_title': self.get_website_title(), 'jarm_hash': self.get_jarm_hash(),
            'whois': self.whois
        }

    # page ranks and subdomains
    def google_index(self):
        try:
            site = search(self.url, num=1)
            if site:
                data = []
                for s in site:
                    data.append(s)
                return {'present_on_google': True, 'site': data}
            else:
                return {'present_on_google': False, 'site': None}
        except:
            return {'present_on_google': "Unknown", 'site': []}


def calculate_probability_of_phishing(summery, html):
    weights = {
        "Suspicious Length": 0.1,
        "URL with @": 0.2,
        "URL with Multiple http": 0.1,
        "URL with PunyCode": 0.3,
        "Hidden Element": 0.05,
        "Hidden Iframe": 0.05,
        "Iframe": 0.1,
        "Suspicious HTML Element": 0.1
    }
    score = 0
    count = 0
    for key, weight in weights.items():
        if count < 4:
            if summery[key]:
                score += weight
        else:
            if html[key]["count"] > 0:
                score += weight
        count += 1
    return score


def complete_output():
    t1 = datetime.datetime.now()
    analyser = Analyser('https://geniobits.com', settings.VIRUS_TOTAL_KEY, settings.GOOGLE_SAFE_BROWSING_KEY)
    t2 = datetime.datetime.now()
    summery = analyser.get_summery()
    t3 = datetime.datetime.now()
    html = analyser.get_html_analysis()
    pp = calculate_probability_of_phishing(summery, html)
    summery["Probability of Phishing"] = pp
    t4 = datetime.datetime.now()
    common = analyser.get_common_analysis()
    t5 = datetime.datetime.now()
    tandd = analyser.get_technology_and_dns_analysis()
    t6 = datetime.datetime.now()
    total_time = (t6 - t1).total_seconds()
    output = {
        'summery': summery, 'html': html, 'common': common, 'tandd': tandd,
        'total_time': total_time
    }
    print(output)
    print(f'Total time taken: {total_time} seconds\n')
    print(f'Percentage of time taken by each function:\n')
    print(f'get_summery: {(t3 - t2).total_seconds() / total_time * 100:.2f}%')
    print(f'get_html_analysis: {(t4 - t3).total_seconds() / total_time * 100:.2f}%')
    print(f'get_common_analysis: {(t5 - t4).total_seconds() / total_time * 100:.2f}%')
    print(f'get_technology_and_dns_analysis: {(t6 - t5).total_seconds() / total_time * 100:.2f}%')
    return output


class AnalyserOutputEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, bytes):
            return obj.decode()
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        return json.JSONEncoder.default(self, obj)


# o = complete_output()
#
# with open("output.json", "w") as f:
#     # Write the JSON data to the file using the "json.dump()" method
#     json.dump(o, f, cls=AnalyserOutputEncoder, indent=4)
