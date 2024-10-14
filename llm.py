from langchain.llms import Ollama
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class APISecurityAnalyzer:
    def __init__(self, model_name="gemma2:latest"):
        self.llm = Ollama(model=model_name)

    def analyze_vulnerability(self, request, response):
        prompt_template = PromptTemplate(
            input_variables=["method", "url", "req_headers", "req_body", "res_status", "res_headers", "res_body"],
            template="""
            Analyze the following API call request and response from security perspective:

            Request:
            Method: {method}
            URL: {url}
            Headers: {req_headers}
            Body: {req_body}

            Response:
            Status: {res_status}
            Headers: {res_headers}
            Body: {res_body}

            Generate security test case specific to this API based on the context from parameters and API path. Only include mostly likely test cases not the generic one's.
            Also suggest possible attacks

            Instruction:
            - Generated test cases should be in bullet points.
            - Do not include anything in response other than security test cases.

            """
        )

        chain = LLMChain(llm=self.llm, prompt=prompt_template)
        
        return chain.run({
            "method": request['method'],
            "url": request['url'],
            "req_headers": request['headers'],
            "req_body": request['body'],
            "res_status": response['status'],
            "res_headers": response['headers'],
            "res_body": response['body']
        })

    def chat(self, api_id, context):
        prompt_template = PromptTemplate(
            input_variables=["context"],
            template="""
            You are an AI assistant specialized in API security analysis. 
            Use the following context to provide a helpful response:

            {context}

            AI: """
        )

        chain = LLMChain(llm=self.llm, prompt=prompt_template)
        
        logging.info(f"API ID: {api_id}")
        logging.info(f"Context sent to LLM: {context}")
        
        response = chain.run(context=context)
        
        logging.info(f"LLM Response: {response}")
        
        return response