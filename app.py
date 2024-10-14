import streamlit as st
import sqlite3
import json
import subprocess
import os
import signal
import requests
import logging
from urllib.parse import urlparse
from llm import APISecurityAnalyzer
from ui import APISecurityUI

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class APISecurityApp:
    def __init__(self):
        self.conn = sqlite3.connect('api_security.db')
        self.analyzer = APISecurityAnalyzer()
        self.ui = APISecurityUI()
        self.init_session_state()
        self.init_database()

    def init_session_state(self):
        if 'proxy_pid' not in st.session_state:
            st.session_state.proxy_pid = None
        if 'analyzed_apis' not in st.session_state:
            st.session_state.analyzed_apis = set()
        if 'code_analysis_config' not in st.session_state:
            st.session_state.code_analysis_config = {
                'endpoint': 'http://localhost:8000/ask',
                'parameter': 'question',
                'value_template': 'From given {endpoint_path} and request body {request_body} identify function in the code which is responsible for the particular API'
            }

    def init_database(self):
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
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_important BOOLEAN DEFAULT 0
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelisted_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_results (
            api_id INTEGER PRIMARY KEY,
            result TEXT,
            FOREIGN KEY (api_id) REFERENCES api_calls (id)
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_id INTEGER,
            message TEXT,
            is_user BOOLEAN,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (api_id) REFERENCES api_calls (id)
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_analysis_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            endpoint TEXT,
            parameter TEXT,
            value_template TEXT
        )
        ''')
        
        # Check if code_analysis_config table is empty and insert default values if needed
        cursor.execute('SELECT COUNT(*) FROM code_analysis_config')
        if cursor.fetchone()[0] == 0:
            default_config = st.session_state.code_analysis_config
            cursor.execute('''
            INSERT INTO code_analysis_config (id, endpoint, parameter, value_template)
            VALUES (1, ?, ?, ?)
            ''', (default_config['endpoint'], default_config['parameter'], default_config['value_template']))
        
        self.conn.commit()

    def save_code_analysis_config(self, endpoint, parameter, value_template):
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT OR REPLACE INTO code_analysis_config (id, endpoint, parameter, value_template)
        VALUES (1, ?, ?, ?)
        ''', (endpoint, parameter, value_template))
        self.conn.commit()
        st.session_state.code_analysis_config = {
            'endpoint': endpoint,
            'parameter': parameter,
            'value_template': value_template
        }

    def get_code_analysis_config(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT endpoint, parameter, value_template FROM code_analysis_config WHERE id = 1')
        result = cursor.fetchone()
        if result:
            return {
                'endpoint': result[0],
                'parameter': result[1],
                'value_template': result[2]
            }
        return st.session_state.code_analysis_config

    def get_code_analysis(self, method, url, request_body):
        config = self.get_code_analysis_config()
        api_endpoint = config['endpoint']
        headers = {"Content-Type": "application/json"}
        
        parsed_url = urlparse(url)
        path = parsed_url.path
        if parsed_url.query:
            path += f"?{parsed_url.query}"
        
        endpoint_path = f"{method} {path}"
        
        logging.info(f"Analyzing endpoint: {endpoint_path}")
        logging.info(f"Request body: {request_body}")
        
        value = config['value_template'].format(endpoint_path=endpoint_path, request_body=request_body)
        data = {
            config['parameter']: value
        }
        
        try:
            logging.info(f"Sending request to {api_endpoint}")
            response = requests.post(api_endpoint, headers=headers, json=data)
            response.raise_for_status()
            logging.info("Received response from code analysis endpoint")
            
            json_response = response.json()
            answer = json_response.get("answer", "No answer provided in the response.")
            logging.info(f"Parsed answer from JSON response: {answer}")
            
            return answer
        except requests.RequestException as e:
            error_message = f"Error getting code analysis: {str(e)}"
            logging.error(error_message)
            return f"Failed to get code analysis. Please try again later. Error: {error_message}"
        except json.JSONDecodeError as e:
            error_message = f"Error parsing JSON response: {str(e)}"
            logging.error(error_message)
            return f"Failed to parse the response. Please try again later. Error: {error_message}"

    def run(self):
        self.ui.run(self)

    def get_whitelisted_domains(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT domain FROM whitelisted_domains")
        return [row[0] for row in cursor.fetchall()]

    def add_whitelisted_domain(self, domain):
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO whitelisted_domains (domain) VALUES (?)", (domain,))
        self.conn.commit()

    def remove_whitelisted_domain(self, domain):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM whitelisted_domains WHERE domain = ?", (domain,))
        self.conn.commit()

    def start_proxy(self):
        if st.session_state.proxy_pid is None:
            process = subprocess.Popen(["mitmdump", "-s", "proxy.py"])
            st.session_state.proxy_pid = process.pid
            st.success("Proxy started")
        else:
            st.warning("Proxy is already running")

    def stop_proxy(self):
        if st.session_state.proxy_pid is not None:
            os.kill(st.session_state.proxy_pid, signal.SIGTERM)
            st.session_state.proxy_pid = None
            st.success("Proxy stopped")
        else:
            st.warning("Proxy is not running")

    def clear_captured_apis(self):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM api_calls")
        cursor.execute("DELETE FROM analysis_results")
        self.conn.commit()
        st.session_state.analyzed_apis.clear()

    def get_api_calls(self, limit=50, offset=0):
        cursor = self.conn.cursor()
        whitelisted_domains = self.get_whitelisted_domains()
        
        if whitelisted_domains:
            placeholders = ', '.join('?' for _ in whitelisted_domains)
            query = f"""
            SELECT * FROM api_calls 
            WHERE {' OR '.join(f"url LIKE '%' || ? || '%'" for _ in whitelisted_domains)}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """
            cursor.execute(query, whitelisted_domains + [limit, offset])
        else:
            cursor.execute("SELECT * FROM api_calls ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_total_api_calls(self):
        cursor = self.conn.cursor()
        whitelisted_domains = self.get_whitelisted_domains()
        
        if whitelisted_domains:
            placeholders = ', '.join('?' for _ in whitelisted_domains)
            query = f"""
            SELECT COUNT(*) FROM api_calls 
            WHERE {' OR '.join(f"url LIKE '%' || ? || '%'" for _ in whitelisted_domains)}
            """
            cursor.execute(query, whitelisted_domains)
        else:
            cursor.execute("SELECT COUNT(*) FROM api_calls")
        
        return cursor.fetchone()[0]

    def get_important_apis(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM api_calls WHERE is_important = 1 ORDER BY id ASC")
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def toggle_api_importance(self, api_id, is_important):
        cursor = self.conn.cursor()
        cursor.execute("UPDATE api_calls SET is_important = ? WHERE id = ?", (is_important, api_id))
        self.conn.commit()

    def remove_api(self, api_id):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM api_calls WHERE id = ?", (api_id,))
        cursor.execute("DELETE FROM analysis_results WHERE api_id = ?", (api_id,))
        self.conn.commit()
        if api_id in st.session_state.analyzed_apis:
            st.session_state.analyzed_apis.remove(api_id)

    def save_analysis_result(self, api_id, analysis):
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO analysis_results (api_id, result) VALUES (?, ?)", (api_id, analysis))
        self.conn.commit()
        st.session_state.analyzed_apis.add(api_id)

    def get_analysis_result(self, api_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT result FROM analysis_results WHERE api_id = ?", (api_id,))
        result = cursor.fetchone()
        return result[0] if result else None

    def get_chat_history(self, api_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT message, is_user FROM chat_history WHERE api_id = ? ORDER BY timestamp ASC", (api_id,))
        return cursor.fetchall()

    def save_chat_message(self, api_id, message, is_user):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO chat_history (api_id, message, is_user) VALUES (?, ?, ?)", (api_id, message, is_user))
        self.conn.commit()

    def chat(self, api_id, message):
        api_call = self.get_api_call(api_id)
        history = self.get_chat_history(api_id)
        context = f"""
        API Request:
        Method: {api_call['method']}
        URL: {api_call['url']}
        Headers: {api_call['request_headers']}
        Body: {api_call['request_body']}

        API Response:
        Status: {api_call['response_status']}
        Headers: {api_call['response_headers']}
        Body: {api_call['response_body']}

        Chat History:
        {json.dumps(history)}

        User: {message}
        """
        response = self.analyzer.chat(api_id, context)
        self.save_chat_message(api_id, message, True)
        self.save_chat_message(api_id, response, False)
        return response

    def clear_chat_history(self, api_id):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM chat_history WHERE api_id = ?", (api_id,))
        self.conn.commit()

    def get_api_call(self, api_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM api_calls WHERE id = ?", (api_id,))
        columns = [column[0] for column in cursor.description]
        return dict(zip(columns, cursor.fetchone()))

    def analyze_api(self, api):
        return self.analyzer.analyze_vulnerability(
            {
                'method': api['method'],
                'url': api['url'],
                'headers': api['request_headers'],
                'body': api['request_body']
            },
            {
                'status': api['response_status'],
                'headers': api['response_headers'],
                'body': api['response_body']
            }
        )

if __name__ == "__main__":
    app = APISecurityApp()
    app.run()