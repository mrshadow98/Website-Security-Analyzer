import asyncio
import json
import re
import socket
import ssl
import string
import traceback
import urllib.parse
from urllib.error import URLError
from urllib.parse import urlparse
import idna
import requests
from bs4 import BeautifulSoup
from dgaintel import get_prob

from PhishingDetection import phishing_detection

import whois
import datetime

from PhishingDetection.phishing_detection import compare_with_google


def get_ip(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(':')[0]
    ip_address = socket.gethostbyname(domain)
    return ip_address


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
        with urllib.request.urlopen(url, context=context) as u:
            cert = u.getpeercert()
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
    def __init__(self, url):
        self.url = url
        # Make a GET request to the URL
        self.response = requests.get(self.url, timeout=3)

        # Parse the HTML content of the response using BeautifulSoup
        self.soup = BeautifulSoup(self.response.content, 'html.parser')
        try:
            self.google_safe_browsing = compare_with_google(self.url, "AIzaSyCcYzRZroIZoq2qdW3tpiSZ3oTDFiRto4U")
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

    def probability_of_phishing(self):
        value = phishing_detection.detect(self.url)
        return value

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
                "URL with Multiple http": self.detect_multiple_http(), "URL with PunyCode": self.detect_punycode(),
                "Probability of Phishing URL": self.probability_of_phishing()}

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

    def find_obfuscated_scripts(self, threshold=0.30):
        try:
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
                return {"count": len(scripts), "elements": scripts, "all_scripts": all_scripts}
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
            patterns = [re.compile(p) for p in [pattern1, pattern2, pattern3, pattern4, pattern5, pattern6, pattern7, pattern8, pattern9, pattern10, pattern11]]

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
                "Credential Input Form": self.check_credential_form(), "Form Event": self.check_suspicious_submit_events(),
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

    def find_domain_location(self):
        # Get the IP address for the domain
        url = "https://ipinfo.io/" + self.ip_address + "/json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data.get("city"), data.get("region"), data.get("country")
        else:
            return None

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

analyser = Analyser("https://geniobits.com")
# print(analyser.get_summery())
# print(analyser.get_html_analysis())
