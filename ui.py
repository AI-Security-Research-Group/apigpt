import streamlit as st
from typing import List, Dict, Callable
import logging
import re
import math

class APISecurityUI:
    def __init__(self):
        if 'refresh_key' not in st.session_state:
            st.session_state.refresh_key = 0
        if 'page_number' not in st.session_state:
            st.session_state.page_number = 1

    def format_code_snippets(self, text):
        # Split the text into code and non-code parts
        parts = re.split(r'(```[\s\S]*?```)', text)
        
        formatted_parts = []
        for part in parts:
            if part.startswith('```') and part.endswith('```'):
                # Extract the code and language (if specified)
                code_lines = part.split('\n')
                if len(code_lines) > 1:
                    lang = code_lines[0].replace('```', '').strip()
                    code = '\n'.join(code_lines[1:-1])
                    formatted_parts.append(st.code(code, language=lang if lang else None))
            else:
                formatted_parts.append(st.markdown(part))
        
        return formatted_parts

    def run(self, app):
        st.set_page_config(layout="wide")
        st.title("API Bee 🐝")

        st.subheader("Code Analysis Configuration")
        config = app.get_code_analysis_config()
        endpoint = st.text_input("Code Analysis Endpoint", value=config['endpoint'])
        parameter = st.text_input("Parameter Name", value=config['parameter'])
        value_template = st.text_area("Value Template", value=config['value_template'])
        
        if st.button("Save Code Analysis Config"):
            app.save_code_analysis_config(endpoint, parameter, value_template)
            st.success("Code analysis configuration saved.")
            self.refresh_ui()

        st.subheader("Proxy Control")

        with st.sidebar:
            st.header("Configuration")
            self.sidebar_config(app)

        self.main_content(app)

    def sidebar_config(self, app):
        st.subheader("Domain Whitelist")
        domain = st.text_input("Enter domain to whitelist")
        if st.button("Add Domain"):
            app.add_whitelisted_domain(domain)
            st.success(f"Added {domain} to whitelist")
            self.refresh_ui()

        st.subheader("Currently Whitelisted Domains")
        whitelisted_domains = app.get_whitelisted_domains()
        for domain in whitelisted_domains:
            col1, col2 = st.columns([3, 1])
            col1.write(domain)
            if col2.button("Remove", key=f"remove_{domain}"):
                app.remove_whitelisted_domain(domain)
                self.refresh_ui()

        st.subheader("Proxy Control")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Start Proxy"):
                app.start_proxy()
        with col2:
            if st.button("Stop Proxy"):
                app.stop_proxy()

        if st.button("Clear Captured APIs"):
            app.clear_captured_apis()
            st.success("All captured APIs have been cleared.")
            self.refresh_ui()

    def main_content(self, app):
        st.header("API List")

        # Pagination
        items_per_page = 50
        total_items = app.get_total_api_calls()
        total_pages = math.ceil(total_items / items_per_page)
        
        col1, col2, col3 = st.columns([1, 3, 1])
        with col1:
            if st.button("Previous Page") and st.session_state.page_number > 1:
                st.session_state.page_number -= 1
                st.rerun()
        with col2:
            st.write(f"Page {st.session_state.page_number} of {total_pages}")
        with col3:
            if st.button("Next Page") and st.session_state.page_number < total_pages:
                st.session_state.page_number += 1
                st.rerun()
        
        offset = (st.session_state.page_number - 1) * items_per_page
        api_calls = app.get_api_calls(limit=items_per_page, offset=offset)

        api_calls = app.get_api_calls()
        if not api_calls:
            st.info("No API calls captured yet. Start the proxy and make some requests to see data here.")
        else:
            for index, api in enumerate(api_calls, start=1):
                api_id = api['id']
                is_analyzed = app.get_analysis_result(api_id) is not None
                is_important = api['is_important']
                icon = "✅" if is_analyzed else "🔄"
                important_icon = "⭐" if is_important else ""
                with st.expander(f"{icon} {important_icon} #{index}: {api['method']} {api['url']}", expanded=False):
                    if st.checkbox("Show Request Headers", key=f"headers_{index}"):
                        st.json(api['request_headers'])
                    if st.checkbox("Show Request Body", key=f"body_{index}"):
                        st.text(api['request_body'])
                    if st.checkbox("Show Response Headers", key=f"resp_headers_{index}"):
                        st.json(api['response_headers'])
                    if st.checkbox("Show Response Body", key=f"resp_body_{index}"):
                        st.text(api['response_body'])

                    col1, col2, col3, col4, col5 = st.columns(5)
                    with col1:
                        if not is_analyzed:
                            if st.button("Analyze", key=f"analyze_{api_id}"):
                                analysis = app.analyze_api(api)
                                app.save_analysis_result(api_id, analysis)
                                st.rerun()
                        else:
                            st.success("This API has been analyzed.")
                    
                    with col2:
                        if st.button("Get Code", key=f"get_code_{api_id}"):
                            logging.info(f"Get Code button clicked for API ID: {api_id}")
                            method = api['method']
                            url = api['url']
                            request_body = api['request_body']
                            code_analysis = app.get_code_analysis(method, url, request_body)
                            st.session_state[f"code_analysis_{api_id}"] = code_analysis
                            st.rerun()           
                    
                    with col3:
                        if st.button("Mark Important" if not is_important else "Unmark Important", key=f"important_{api_id}"):
                            app.toggle_api_importance(api_id, not is_important)
                            self.refresh_ui()
                    
                    with col4:
                        if st.button("Remove API", key=f"remove_api_{api_id}"):
                            app.remove_api(api_id)
                            self.refresh_ui()

                    with col5:
                        if st.button("Clear Chat", key=f"clear_chat_{api_id}"):
                            app.clear_chat_history(api_id)
                            self.refresh_ui()                            

                    # Display code analysis with properly formatted code snippets
                    if f"code_analysis_{api_id}" in st.session_state:
                        st.markdown("---")
                        st.markdown("### Code Analysis")
                        analysis_text = st.session_state[f"code_analysis_{api_id}"]
                        
                        # Use a container for better width control
                        with st.container():
                            st.markdown("""
                            <style>
                            .stMarkdown {
                                max-width: 100%;
                            }
                            .stCodeBlock {
                                max-width: 100%;
                            }
                            </style>
                            """, unsafe_allow_html=True)
                            
                            self.format_code_snippets(analysis_text)
                        
                        st.markdown("---")

                    analysis_result = app.get_analysis_result(api_id)
                    if analysis_result:
                        st.subheader("Analysis Result")
                        st.markdown(analysis_result)

                    st.subheader("Chat")
                    chat_history = app.get_chat_history(api_id)
                    for message, is_user in chat_history:
                        st.text(f"{'User' if is_user else 'AI'}: {message}")

                    chat_input = st.text_input("Chat Input", key=f"chat_input_{api_id}")
                    if st.button("Send", key=f"send_{api_id}"):
                        response = app.chat(api_id, chat_input)
                        st.markdown(f"AI: {response}")
                        self.refresh_ui()

        st.header("Important APIs")
        important_apis = app.get_important_apis()
        if not important_apis:
            st.info("No APIs marked as important yet.")
        else:
            for api in important_apis:
                st.write(f"#{api['id']}: {api['method']} {api['url']}")

    def refresh_ui(self):
        st.session_state.refresh_key += 1