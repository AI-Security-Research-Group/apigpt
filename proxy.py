import mitmproxy.http
import sqlite3
import json
from urllib.parse import urlparse
import logging
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class APISecurityProxy:
    def __init__(self, db_path='api_security.db'):
        self.conn = sqlite3.connect(db_path)
        self.create_table()
        self.debug_mode = False
        self.whitelisted_domains = self.load_whitelisted_domains()

    def load_whitelisted_domains(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT domain FROM whitelisted_domains")
        return [row[0] for row in cursor.fetchall()]

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT,
            url TEXT,
            request_headers TEXT,
            request_body TEXT,
            response_status INTEGER,
            response_headers TEXT,
            response_body TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        self.conn.commit()

    def request(self, flow: mitmproxy.http.HTTPFlow):
        logging.info(f"Intercepted request: {flow.request.method} {flow.request.url}")

    def response(self, flow: mitmproxy.http.HTTPFlow):
        domain = urlparse(flow.request.url).netloc
        logging.info(f"Intercepted response: {flow.request.method} {flow.request.url} - Status: {flow.response.status_code}")
        
        if self.is_domain_whitelisted(domain) or self.debug_mode:
            logging.info(f"Capturing domain: {domain}")
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT INTO api_calls (method, url, request_headers, request_body, response_status, response_headers, response_body)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    flow.request.method,
                    flow.request.url,
                    json.dumps(dict(flow.request.headers)),
                    flow.request.content.decode('utf-8', 'ignore'),
                    flow.response.status_code,
                    json.dumps(dict(flow.response.headers)),
                    flow.response.content.decode('utf-8', 'ignore')
                ))
                self.conn.commit()
                logging.info(f"Successfully captured API call: {flow.request.method} {flow.request.url}")
            except sqlite3.Error as e:
                logging.error(f"Database error: {e}")
            except Exception as e:
                logging.error(f"Error capturing API call: {e}")
        else:
            logging.info(f"Domain not whitelisted, skipping capture: {domain}")

    def is_domain_whitelisted(self, domain):
        for whitelisted_domain in self.whitelisted_domains:
            if re.match(f"^{re.escape(whitelisted_domain).replace('\\*', '.*')}$", domain):
                return True
        return False

addons = [APISecurityProxy()]