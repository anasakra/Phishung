#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')

import pickle
import pandas as pd


file_path ='pickle\model.pkl'
# فتح الملف وقراءة النموذج
with open(file_path, 'rb') as file:
    model = pickle.load(file)

#importing required packages for this module
import pandas as pd
# importing required packages for this section
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse, urlsplit, urlunsplit
import googlesearch
import dns.resolver
from tldextract import extract
from collections import Counter
import json
import ssl
import regex
from urllib.parse import urlparse, urlsplit, urlunsplit
import requests
import re
from bs4 import BeautifulSoup
import tldextract
import pandas as pd
from urllib.parse import urlparse, urlencode
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
import dns.resolver
from tldextract import extract
from collections import Counter
import json
import ssl
import tldextract
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry







# الدالة لاستخراج النطاق من عنوان URL
def extract_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path 
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# الدالة للتحقق مما إذا كان عنوان URL يحتوي على عنوان IP
def having_ip_address(url):
    try:
        # استخدام الدالة extract_domain لاستخراج النطاق
        domain = extract_domain(url)
        
        # التحقق مما إذا كان النطاق يحتوي على عنوان IP
        match = re.search(r'\d+\.\d+\.\d+\.\d+', domain)
        
        if match:
            return 1  # يشير إلى حالة وجود IP
        else:
            return -1  # يشير إلى حالة عدم وجود IP
    except Exception as e:
        return 0  # يشير إلى حدوث خطأ
def URL_Length(url): 
    if len(url) < 54: 
        return -1 
    elif len(url) >= 54 and len(url) <=75: 
        return 0 
    else: return 1
    
def isShortUrl(url):
    try:
        domain = extract_domain(url)
        short_domains = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd',
            'shorte.st', 'go2l.ink', 'x.co', 'cli.gs', 'yfrog.com', 'migre.me',
            'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
            'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com',
            'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'short.ie', 'kl.am',
            'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 'lnkd.in', 'db.tt',
            'qr.ae', 'adf.ly', 'cur.lv', 'ity.im', 'q.gs', 'po.st', 'bc.vc',
            'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb',
            'yourls.org', 'prettylinkpro.com', 'scrnch.me', 'filoops.info',
            'vzturl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd', 'tr.im',
            'link.zip.net', 'short.gy','shorturl.at','t.ly','rb.gy'
        ]
        for short_domain in short_domains:
            if domain.endswith(short_domain):
                return 1
        return -1
    except:
        return 0

# 5.Checks the presence of @ in URL
def symbol(url):
    if re.findall("@", url):
        return 1
    return -1

# 6.Checking for redirection '//' in the url
def redirection(url):
    try:
        parsed_url = urlparse(url)
        protocol = parsed_url.scheme.lower()  # Extract protocol (http or https)
        pos = url.rfind('//')       # Find all occurrences of "//"
        if (protocol == "http" and pos > 6) or (protocol == "https" and pos > 7):
            return 1  
        else:
            return -1
    except:
        return 0
    
# 7.Checking for Prefix or Suffix Separated by (-) in the Domain
def prefixSuffix(url):
    domain = extract_domain(url)
        
    if '-' in domain:
        return 1  # phishing
    else:
        return -1 # legitimate
    
# 8.Checking for Multi Sub Domains in the url
def SubDomains(url):
    try:
        domain = extract_domain(url)
        # Separate domain parts based on dots
        domain_parts = domain.split(".")
       
          # Count dots (excluding TLD)
        num_dots = len(domain_parts) - 2  # Subtract 1 for TLD and 1 for root domain

        if num_dots == 0:
            return -1  # No subdomains
        elif num_dots == 1:
            return 0  # One subdomain
        else:
            return 1  # Two or more subdomains
    except:
        return 0
#   9- ssl
def SSLfinal_State(url):
    
    try:
          
        # Check if the URL starts with 'https'
        if url.startswith('https'):
            use_https = 1
        else:
            use_https = -1
            
        domain = extract_domain(url)
        
        # Create a secure connection context
        context = ssl.create_default_context()

        # Wrap the socket with SSL layer
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
      
        
        # Connect to the host
        conn.connect((domain, 443))
       

        # Get the SSL certificate
        certificate = conn.getpeercert()

        # Extract the issuer name if available
        if 'issuer' in certificate:
            issuer = dict(x[0] for x in certificate['issuer'])
            certificate_auth = str(issuer.get('commonName', ''))
            certificate_auth = certificate_auth.split()
            if certificate_auth[0] == "Network" or certificate_auth[0] == "Deutsche":
                certificate_auth = certificate_auth[0] + " " + certificate_auth[1]
            else:
                certificate_auth = certificate_auth[0]
              
        else:
            certificate_auth = ''

        # List of trusted certificate authorities
        trusted_auth = ['Comodo', 'Symantec', 'AlphaSSL', 'GoDaddy', 'Amazon', 'GlobalSign',
                        'DigiCert', 'StartCom', 'Entrust', 'Verizon', 'Trustwave', 'Unizeto',
                        'Buypass', 'QuoVadis', 'Deutsche Telekom', 'Network Solutions', 'SwissSign',
                        'IdenTrust', 'Secom', 'TWCA', 'GeoTrust', 'Thawte', 'Doster','Verisign',
                        'VeriSign', 'Let\'s Encrypt', 'GTS', 'SSL.com', 'RapidSSL', 'Sectigo',
                        'Starfield', 'eNom', 'Namecheap', '1&1 IONOS', 'Hostinger', 'A2 Hosting',
                        'Bluehost', 'DreamHost', 'GreenGeeks', 'InMotion Hosting', 'InterServer', 'Liquid Web',
                        'Media Temple', 'MilesWeb', 'Nexcess', 'SiteGround', 'WP Engine', 'COMODO','E1','WR2','digiCert','NeTrust']

        # Extract the certificate validity dates
        starting_date = datetime.strptime(certificate['notBefore'], "%b %d %H:%M:%S %Y %Z")
    
        ending_date = datetime.strptime(certificate['notAfter'], "%b %d %H:%M:%S %Y %Z")
        
        # Calculate the number of days between the start and end dates
        num_days = (ending_date - starting_date).days
      

        # Check the final conditions
        if use_https == 1 and certificate_auth in trusted_auth and num_days >= 83:
            return -1  # legitimate
        elif use_https == 1 and certificate_auth not in trusted_auth:
            return 0  # suspicious
           
        else:
            return 1  # phishing
    except ssl.SSLError as e:
     
        return 1
    except socket.gaierror as e:
       
        return 1
    except Exception as e:
        
        return 0  

# 10 -
def domain_registration_length(domain_name):
    try:
       
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]  # Take the first element of the list
            if isinstance(expiration_date, str):
                expiration_date = expiration_date.lstrip(': ').strip()  # Remove leading colon and spaces
                try:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')  # Convert string to datetime
                except ValueError:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')  # Try without time component
                
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]  # Take the first element of the list
            if isinstance(creation_date, str):
                creation_date = creation_date.lstrip(': ').strip()  # Remove leading colon and spaces
                try:
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S') # Convert string to datetime
                except ValueError:
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d')  # Try without time component

        ageofdomain = abs((expiration_date - creation_date).days) if expiration_date and creation_date else 0
      
        if ageofdomain < 367:
            return 1
        else:
            return -1
    
    except:
     
        return 0
    
# 11.Checking for Favicon
import warnings

def Favicon(response,url):
    if response == "":
        return 1
    else:
        # تحليل محتوى الصفحة باستخدام مكتبة BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # تحليل عنوان URL باستخدام مكتبة urlparse
        parsed_urll = urlparse(url)
        
        # البحث عن جميع العناصر <head> في الصفحة
        for head in soup.find_all('head'):
            # البحث عن جميع العناصر <link> داخل العنصر <head> التي تحتوي على السمة href
            for link in head.find_all('link', href=True):
                # تحليل الرابط الموجود في السمة href للعناصر <link>
                parsed_link = urlparse(link['href'])
                
                # التحقق مما إذا كان النطاق (netloc) للرابط المفسر يساوي النطاق لعنوان URL الأصلي أو المسار (path) يساوي المسار لعنوان URL الأصلي
                if parsed_link.netloc == url or parsed_link.path == parsed_urll.path:
                    return -1  # العثور على فافيكون على نفس النطاق أو نفس المسار
        return 1  # لم يتم العثور على فافيكون على نفس النطاق أو نفس المسار


 # 12.Checking for port


def port(url):
    try:
        domain = extract_domain(url)       
        api_key = "41455c8105382f6c69de59342367ce76f4760b9c"
        api_url = f"https://api.viewdns.info/portscan/?host={domain}&apikey={api_key}&output=json"
        
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        
        myjson = response.json()
        
        pref_stat = {21: 'closed', 22: 'closed', 23: 'closed', 80: 'open', 443: 'open',
                     445: 'closed', 1433: 'closed', 1521: 'closed', 3306: 'closed', 3389: 'closed'} 
        flag = -1
        
        for port_data in myjson.get('response', {}).get('port', []):
            port_number = int(port_data['number'])
            port_status = port_data['status']
            if port_number in pref_stat:
                if port_status != pref_stat[port_number]:
                    flag = 1
                    break  # Exit loop once a mismatch is found
        
        return flag 
    except Exception as e:
       
        return 0

# 13.Checking for httsp Token in the Domain Part
def httpsDomain(url):
    try:
        domain = extract_domain(url)
     
        if 'https' in domain:
            return 1
        else:
            return -1
    except:
        return 0
# 14.Gives number of '/' in URL 
def too_deep_url(url):
    try:
        slashes = -2 # to skip first two slashes after protocol, i.e. https://
        for i in url:
            if i == '/':
                slashes += 1
        if slashes > 5:
            return 1
        else:
            return -1
    except:
        return 0
# 15.Checking for request_url
def request_url(response,url):

    if response == "":
        return 1
    else:
      
        Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever", "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]

        def is_URL_accessible(url):
            try:
                page = requests.get(url, timeout=5)
                if page.status_code == 200 and page.content:
                   
                    return True, url, page.content
            except:
                parsed = urlparse(url)
                url = parsed.scheme+'://'+parsed.netloc
                if not parsed.netloc.startswith('www'):
                    url = parsed.scheme+'://www.'+parsed.netloc
                try:
                    page = requests.get(url, timeout=5)
                    if page.status_code == 200 and page.content:
                        return True, url, page.content
                except:
                    pass
            return False, None, None

        def get_domain(url):
            o = urlsplit(url)
            
            return o.hostname, tldextract.extract(url).domain, o.path

        state, iurl, content = is_URL_accessible(url)
       
        if state:
            hostname, domain, path = get_domain(url)
            
        else:
            return 1

        Media = {'internals':[], 'externals':[], 'null':[]}

        def external_media(Media):
            total = len(Media['internals']) + len(Media['externals'])
            externals = len(Media['externals'])
            try:
                percentile = externals / float(total) * 100
            except:
                return 0
            return percentile

        def findMedia(Media, domain, hostname):
            soup = BeautifulSoup(content, 'html.parser', from_encoding='iso-8859-1')
            for img in soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                
                if hostname in img['src'] or domain in img['src'] or len(dots) == 1 or not img['src'].startswith('http'):
                    if not img['src'].startswith('http'):
                        if not img['src'].startswith('/'):
                            Media['internals'].append(hostname+'/'+img['src'])
                        elif img['src'] in Null_format:
                            Media['null'].append(img['src'])
                        else:
                            Media['internals'].append(hostname+img['src'])
                    else:
                        Media['externals'].append(img['src'])

            for audio in soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if hostname in audio['src'] or domain in audio['src'] or len(dots) == 1 or not audio['src'].startswith('http'):
                    if not audio['src'].startswith('http'):
                        if not audio['src'].startswith('/'):
                            Media['internals'].append(hostname+'/'+audio['src'])
                        elif audio['src'] in Null_format:
                            Media['null'].append(audio['src'])
                        else:
                            Media['internals'].append(hostname+audio['src'])
                    else:
                        Media['externals'].append(audio['src'])

            for embed in soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if hostname in embed['src'] or domain in embed['src'] or len(dots) == 1 or not embed['src'].startswith('http'):
                    if not embed['src'].startswith('http'):
                        if not embed['src'].startswith('/'):
                            Media['internals'].append(hostname+'/'+embed['src'])
                        elif embed['src'] in Null_format:
                            Media['null'].append(embed['src'])
                        else:
                            Media['internals'].append(hostname+embed['src'])
                    else:
                        Media['externals'].append(embed['src'])

            for i_frame in soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', i_frame['src'])]
                if hostname in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1 or not i_frame['src'].startswith('http'):
                    if not i_frame['src'].startswith('http'):
                        if not i_frame['src'].startswith('/'):
                            Media['internals'].append(hostname+'/'+i_frame['src'])
                        elif i_frame['src'] in Null_format:
                            Media['null'].append(i_frame['src'])
                        else:
                            Media['internals'].append(hostname+i_frame['src'])
                    else:
                        Media['externals'].append(i_frame['src'])

        findMedia(Media, domain, hostname)

        if external_media(Media) < 22:
          
            return -1
        elif external_media(Media) >= 22 and external_media(Media) < 61:
            return 0
        else:

            return 1

# 16.Checking for URL of Anchor
def url_of_anchor(response,url):

    if response == "":
        return 1
    else:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain
        
      
        content = response.text
        soup = BeautifulSoup(content, 'lxml')
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        avg = 0
        for anchor in anchors:
            try:
                subDomain, domain, suffix = extract(anchor['href'])
                anchorDomain = domain
                if websiteDomain == anchorDomain or anchorDomain == '':
                    linked_to_same += 1
            except:
                continue

        linked_outside = total - linked_to_same
        if total != 0:
            avg = linked_outside / total

        if avg < 0.31:
            return -1
        elif 0.31 <= avg <= 0.67:
            return 0
        else:
            return 1
 
 
def LinksInTags(response,url):
    if response == "":
        return 1
    else:
        soup = BeautifulSoup(response.content, 'html.parser')
        
        success = 0  # Count of internal/local links
        total = 0     # Total number of links

        for link in soup.find_all('link', href=True):
            href = link['href']
            if href and (url in href or href.startswith('/') or len(href.split('.')) == 1):
                success += 1
                total += 1
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src and (url in src or src.startswith('/') or len(src.split('.')) == 1):
                success += 1
                total += 1
        if total > 0:
            percentage = (success / total) * 100
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1
        else:
          # Handle case where no links are found
          return 0
    
# 18.Checking for Server Form Handler
def ServerFormHandler(response,url):
 
    if response == "":
        return 1
    else:   
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        if len(soup.find_all('form', action=True)) == 0:
            return 0
        else:
            domain = urlparse(url).netloc
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return 0
                elif url not in form['action'] and domain not in form['action']:
                    return 1
            return -1
# 19.Checking for Submitting Information to Email
def email_submit(opener,url):
    if opener == "":
        return 1
    else:
        soup = BeautifulSoup(opener, 'lxml')
        if soup.find('a', href=lambda href: href and href.startswith('mailto:')):
            return 1
        else:
            return -1

# 20. Checking for Abnormal URL
def abnormal_url(domain_names, url):
    domain = extract_domain(url)
    
    # Extract the registered domain name
    registered_domain = domain_names.domain_name
    
    if registered_domain is None:
        return 1  # Assuming 1 indicates an abnormal URL when no domain info is available
    
    # If registered_domain is a list, join it into a single string for comparison
    if isinstance(registered_domain, list):
        registered_domain = ' '.join(registered_domain)
        
    # Ensure both domain and registered_domain are compared in lowercase
    if domain.lower() in registered_domain.lower():
        return -1
    else:
        return 1

# 21.Checking for Status Bar Customization
def StatusBarCust(response):
    if response == "":
        return 1
    else:
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        elements = soup.find_all(attrs={'onmouseover': True})

        if len(elements) > 0:
            return 1
        else:
            return -1

# 22.Checking for Right Click
def rightClick(opener):

    if opener == "":
        return 1
    else:
        soup = BeautifulSoup(opener, 'lxml')
        s = str(soup)
        if (re.search("contextmenu", s) and re.search("preventDefault()", s)):
            return 1
        else:
            return -1

# 23.Checking for Using Pop-up Window
def UsingPopupWindow(response):
    if response == "":
        return 1
    else:
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        s = str(soup)
        if re.search("alert", s):
            return 1
        else:
            return -1
  
# 24.Checking for IFrame Redirection
def IframeRedirection(response):
    if response == "":
        return 1
    else:
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        s = str(soup)
        if (re.search("iframe", s) or re.search("frameBorder()", s)):
            return 1
        else:
            return -1
 
# 25

def domainAge(domain_name):
    try:
        today = datetime.today()
        
        expiration_date = domain_name.expiration_date
        
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]  # Take the first element of the list
            if isinstance(expiration_date, str):
                expiration_date = expiration_date.lstrip(': ').strip()  # Remove leading colon and spaces
                try:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')  # Convert string to datetime
                except ValueError:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')  # Try without time component
                
       
        registration_length = abs((expiration_date - today).days) if expiration_date else 0
      
        if registration_length <= 180:
            return 1
        else:
            return -1
    except:
     
        return 0
# 26.Checking for DNS Record

def check_dns_record(url):
    try:
        domain = extract_domain(url)
        
        socket.gethostbyname(domain)
        return -1  
    except socket.gaierror:
        return 1  
    except:
        return 0 


def WebsiteTraffic(url):
    domain = extract_domain(url)  
    
    api_key = '0816cb0da25e4a3dbda0e12060bdf981'  # استبدل بـ API Key الخاص بك من Similarweb
    try:
      
                        # إعداد عنوان الطلب إلى Similarweb
        api_url = f'https://api.similarweb.com/v1/similar-rank/{domain}/rank?api_key={api_key}&format=json'
    
                        # إرسال طلب API إلى Similarweb للحصول على تصنيف الموقع
        response = requests.get(api_url)
                        # التحقق من وجود أخطاء في الاستجابة
        if response.status_code ==  404:
            return 1
        response.raise_for_status()  # التحقق من وجود أخطاء HTTP
         
        data = response.json()
                        # استخراج التصنيف من الاستجابة
        rank = data.get('similar_rank', {}).get('rank', 0)
     
         
        if rank <= 100000:
            return -1  # إذا كان التصنيف أقل من أو يساوي 100,000، نعتبر أن الموقع له حركة مرور عالية
        else:
            return 1  # إذا كان التصنيف أعلى من 100,000، نعتبر أن الموقع ليس له حركة مرور كبيرة
    except :
         
        return 0  # 
    
# 28.Checking for Page Rank 
def page_rank(url):
    domain = extract_domain(url)  
    key = 'sgow0socgkskow48kcw88ws0swks0sgsowocsowg'  # Replace with your actual API key
    api_url = f'https://openpagerank.com/api/v1.0/getPageRank?domains[0]={domain}'
    
    # Create a session with retry logic
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    
    try:
        response = session.get(api_url, headers={'API-OPR': key}, timeout=60)
        response.raise_for_status()  # Raise an HTTPError on bad response
        data = response.json()
        if data['response'][0]['status_code'] == 200:
        # Extract page rank value as needed from the response
            result = data['response'][0]['page_rank_decimal'] if data['response'] else None
     
            if result / 10 <= 0.2:
                return 1
            else:
                return -1
        else:
            return 1
    except requests.exceptions.HTTPError as http_err:
        return 1
    except requests.exceptions.ConnectionError as conn_err:
        return 1
    except requests.exceptions.Timeout as timeout_err:
        return 1
    except requests.exceptions.RequestException as req_err:
        return 1
    return 1
# 29.Checking for google Index
def googleIndex(url):
    print("the url is:",url)
    domain = extract_domain(url)
    print("the domain is:",domain)
    api_key='a2b8013ead678b5f0cdf77521a9f4e11'
    query = f'site:{domain}'
    payload = {
        'api_key': api_key,
        'url': f'https://www.google.com/search?q={query}&hl=en'
    }

    try:
        # إرسال الطلب إلى ScraperAPI
        response = requests.get('https://api.scraperapi.com', params=payload)

        # تحقق من نجاح الطلب
        if response.status_code == 200:
            # تحليل الرد للتحقق من فهرسة النطاق
            if 'did not match any documents' in response.text:
                return 1  # النطاق غير مفهرس
            else:
                return -1  # النطاق مفهرس
        else:
        
            return 0  # فشل في التحقق من فهرسة النطاق
    except Exception as e:
        
        return 0 
    
# 30.Checking for Links Pointing To Page
def LinksPointingToPage(response):
    if response == "":
        return 1
    else:
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        s = str(soup)
       
        found_urls = Counter([link["href"] for link in soup.find_all("a", href=lambda href: href and not href.startswith("#"))])
        count = len(found_urls)

        if count > 2:
            return -1
        if 0 < count <= 2 :
            return 0
        else:
            return 1

import numpy as np
import pandas as pd

# Example feature names - تأكد من أنها تحتوي على 29 اسمًا
feature_names = [ 'having_ip_address', 'URL_Length', 'isShortUrl', 'symbol',
       'redirection', 'prefixSuffix', 'SubDomains', 'SSLfinal_State',
       'domain_registration_length', 'Favicon', 'port', 'httpsDomain',
       'too_deep_url', 'request_url', 'url_of_anchor', 'LinksInTags',
       'ServerFormHandler', 'email_submit', 'abnormal_url', 'StatusBarCust',
       'rightClick', 'UsingPopupWindow', 'IframeRedirection', 'domainAge',
       'check_dns_record', 'WebsiteTraffic', 'page_rank', 'googleIndex',
       'LinksPointingToPage']

# Function to extract features
def featureExtraction(url):
    features = []
    # Add feature extraction functions
    features.append(having_ip_address(url))
    features.append(URL_Length(url))
    features.append(isShortUrl(url))
    features.append(symbol(url))
    features.append(redirection(url))
    features.append(prefixSuffix(url))
    features.append(SubDomains(url))
    features.append(SSLfinal_State(url))

    dns = 0
    try:
        domain_names = whois.whois(extract_domain(url))
    except:
        dns = 1
        domain_names = None
    features.append(1 if dns == 1 else domain_registration_length(domain_names))
    
    try:
        response = requests.get(url)
    except:
        response = ""
    features.append(Favicon(response, url))
    features.append(port(url))
    features.append(httpsDomain(url))
    features.append(too_deep_url(url))
    features.append(request_url(response, url))
    features.append(url_of_anchor(response, url))
    features.append(LinksInTags(response, url))
    features.append(ServerFormHandler(response, url))
    try:
        opener = urllib.request.urlopen(url).read()
    except:
        opener = ""
    features.append(email_submit(opener, url))
    features.append(1 if dns == 1 else abnormal_url(domain_names, url))
    features.append(StatusBarCust(response))
    features.append(rightClick(opener))
    features.append(UsingPopupWindow(response))
    features.append(IframeRedirection(response))

    features.append(1 if dns == 1 else domainAge(domain_names))
    features.append(check_dns_record(url))
    features.append(WebsiteTraffic(url))
    features.append(page_rank(url))
    features.append(googleIndex(url))
    features.append(LinksPointingToPage(response))

    return features



app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        url = request.form["url"]
        
        features = featureExtraction(url)
        features = np.array(features).reshape(1, -1)


        

        prediction = model.predict(features)
        phishing_probb = model.predict_proba(features)
        non_phishing_probb = model.predict_proba(features)
        
        phishing_prob = phishing_probb[0,1]
        non_phishing_prob = non_phishing_probb[0,0]
        
        output = prediction[0]

        if output == 1:
            print("Caution! Suspicious website detected",phishing_prob*100)
        else:
           print("We guess it is a safe website",non_phishing_prob*100)

        
    
        # if(y_pred ==1 ):
        
        return render_template('index.html',xx = round(phishing_prob,4),url=url )
    return render_template("index.html", xx =-1)


if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)

