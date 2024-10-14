# API Bee 🐝

API Bee is your co-pilot for API security testing, helping you brainstorm and manage the test cases.

## Screenshot
<img width="850" alt="Screenshot 2024-10-07 at 5 10 21 PM" src="https://github.com/user-attachments/assets/a07cce45-1ae9-479f-96d7-6b9b345607e4">

## Key Features

- Automated security analysis and test cases of captured APIs
- Real-time API call capture via MITM proxy - Click start and you are done.
- Domain whitelisting for focused testing - Remove the noise.
- Mark and track important APIs - Work on only what matters to you.
- Integrated chat interface for in-depth analysis - Got your back 

## How it Works

1. Captures API calls using a MITM proxy
2. Stores captured calls in a SQLite database
3. Analyzes APIs for write specific security test cases using LLM
4. Presents results through an intuitive Streamlit UI

## Prerequisites

- Python 3.7+
- mitmproxy
- Streamlit
- SQLite3

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/AI-Security-Research-Group/apilot.git
   cd apilot
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Start the application:
   ```
   streamlit run app.py
   ```

2. Use the sidebar to configure domain whitelist and start the proxy
3. After starting proxy browse through browser. **Proxy runs on :8080 port**
4. Make API calls through the configured proxy
5. Analyze captured APIs and view results in the main interface

## Acknowledgments

- Streamlit for the UI framework
- mitmproxy for API interception
- LangChain and Ollama for LLM integration
