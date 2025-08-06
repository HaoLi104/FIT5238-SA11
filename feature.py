import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois

from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self,url):
        self.features = []
        self.reasons = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.urlparse.netloc)
            self.reasons.append("URL is using an IP address, which can be suspicious.")
            return -1
        except:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        self.reasons.append("URL is very long, which is a common tactic for phishing sites.")
        return -1

    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            self.reasons.append("URL uses a shortening service, which can hide the real destination.")
            return -1
        return 1

    def symbol(self):
        if re.findall("@",self.url):
            self.reasons.append("URL contains an '@' symbol, which can be misleading.")
            return -1
        return 1
    
    def redirecting(self):
        if self.url.rfind('//')>6:
            self.reasons.append("URL uses '//' for redirection, which could lead to a malicious site.")
            return -1
        return 1
    
    def prefixSuffix(self):
        try:
            match = re.findall(r'\-', self.domain)
            if match:
                self.reasons.append("Domain name contains a '-' symbol, which is sometimes used by phishing sites.")
                return -1
            return 1
        except:
            return -1
    
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        self.reasons.append("URL has a high number of subdomains, which can be a sign of phishing.")
        return -1

    def Hppts(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            self.reasons.append("Website does not use HTTPS, making it less secure.")
            return -1
        except:
            return 1

    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list): expiration_date = expiration_date[0]
            if isinstance(creation_date, list): creation_date = creation_date[0]

            age = (expiration_date.year-creation_date.year)*12 + (expiration_date.month-creation_date.month)
            if age >= 12:
                return 1
            else:
                self.reasons.append("Domain registration period is less than one year, which is suspicious.")
                return -1
        except:
            return -1

    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    if self.urlparse.netloc in link['href'] or len(link['href'].split('.')) == 2 :
                        return 1
            self.reasons.append("Favicon is loaded from a different domain, which could be a sign of phishing.")
            return -1
        except:
            return -1

    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1 and port[1] not in ['80', '443']:
                self.reasons.append("Website is using a non-standard port.")
                return -1
            return 1
        except:
            return -1

    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                self.reasons.append("Domain name itself contains 'https', which is a deceptive tactic.")
                return -1
            return 1
        except:
            return -1
    
    def RequestURL(self):
        try:
            i, success = 0, 0
            for img in self.soup.find_all('img', src=True):
                i += 1
                if self.urlparse.netloc in img['src']:
                    success += 1
            for audio in self.soup.find_all('audio', src=True):
                i += 1
                if self.urlparse.netloc in audio['src']:
                    success += 1
            for embed in self.soup.find_all('embed', src=True):
                i += 1
                if self.urlparse.netloc in embed['src']:
                    success += 1
            for iframe in self.soup.find_all('iframe', src=True):
                i += 1
                if self.urlparse.netloc in iframe['src']:
                    success += 1
            
            if i == 0: return 1
            percentage = success / float(i) * 100
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            else:
                self.reasons.append("A high percentage of media assets are not hosted on the main domain.")
                return -1
        except:
            return -1
    
    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                i += 1
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
            
            if i == 0: return 1
            percentage = unsafe / float(i) * 100
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            else:
                self.reasons.append("A high percentage of links are suspicious (e.g., empty or pointing to other domains).")
                return -1
        except:
            return -1

    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
            for link in self.soup.find_all('link', href=True):
                i += 1
                if self.urlparse.netloc in link['href']:
                    success += 1
            for script in self.soup.find_all('script', src=True):
                i += 1
                if self.urlparse.netloc in script['src']:
                    success += 1

            if i == 0: return 1
            percentage = success / float(i) * 100
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                self.reasons.append("A high percentage of scripts are loaded from different domains.")
                return -1
        except:
            return -1

    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True)) == 0:
                return 1
            else:
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        self.reasons.append("A form on the page submits to an empty or blank page, which is highly suspicious.")
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    def InfoEmail(self):
        try:
            if re.findall(r"mailto:", self.response.text):
                self.reasons.append("Page contains 'mailto' links, which can be used for phishing attacks.")
                return -1
            else:
                return 1
        except:
            return -1

    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                self.reasons.append("The WHOIS information does not match the website's content.")
                return -1
        except:
            return -1

    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                self.reasons.append("The website has a high number of redirects, which can be a cloaking technique.")
                return -1
        except:
             return -1

    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                self.reasons.append("The website attempts to customize the status bar, a known phishing tactic.")
                return 1
            else:
                return -1
        except:
             return -1

    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                self.reasons.append("Right-click has been disabled, which can be an attempt to hide source code.")
                return 1
            else:
                return -1
        except:
             return -1

    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                self.reasons.append("The page uses pop-up windows, which can be used for malicious purposes.")
                return 1
            else:
                return -1
        except:
             return -1

    def IframeRedirection(self):
        try:
            if re.findall(r"<iframe>|<frameBorder>", self.response.text):
                self.reasons.append("The page uses iframes, which can be used to conceal malicious content.")
                return 1
            else:
                return -1
        except:
             return -1

    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            self.reasons.append("The domain is less than 6 months old, which is common for phishing sites.")
            return -1
        except:
            return -1

    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            if self.whois_response == "":
                self.reasons.append("Could not find DNS records for the domain.")
                return -1
            return 1
        except:
            self.reasons.append("DNS record query failed, which could indicate a non-existent or suspicious domain.")
            return -1

    def WebsiteTraffic(self):
        # This feature is deprecated as Alexa API is no longer available.
        return 1

    def PageRank(self):
        # This feature is deprecated as Google PageRank is no longer publicly available.
        return 1

    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                self.reasons.append("The website is not indexed by Google, which is suspicious for a legitimate site.")
                return -1
        except:
            return 1

    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                self.reasons.append("There are very few or no links pointing to this page, indicating it might not be a legitimate part of a website.")
                return -1
        except:
            return -1

    def StatsReport(self):
        try:
            url_match = re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            if url_match:
                self.reasons.append("The domain is on a list of known malicious hosting providers.")
                return -1
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158', ip_address)
            if ip_match:
                self.reasons.append("The website's IP address is on a blacklist of known phishing servers.")
                return -1
            return 1
        except:
            return 1
    
    def getFeaturesList(self):
        return [self.UsingIp(), self.longUrl(), self.shortUrl(), self.symbol(), self.redirecting(), self.prefixSuffix(), self.SubDomains(), self.Hppts(), self.DomainRegLen(), self.Favicon(), self.NonStdPort(), self.HTTPSDomainURL(), self.RequestURL(), self.AnchorURL(), self.LinksInScriptTags(), self.ServerFormHandler(), self.InfoEmail(), self.AbnormalURL(), self.WebsiteForwarding(), self.StatusBarCust(), self.DisableRightClick(), self.UsingPopupWindow(), self.IframeRedirection(), self.AgeofDomain(), self.DNSRecording(), self.WebsiteTraffic(), self.PageRank(), self.GoogleIndex(), self.LinksPointingToPage(), self.StatsReport()]

    def getRiskReasons(self):
        return self.reasons
