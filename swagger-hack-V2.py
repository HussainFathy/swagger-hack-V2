# add auth token manually if -t didn't work search for -> Bearer ADD-Token-Here
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, os, re
import sys
from urllib.parse import urlparse, urljoin
import requests
import csv
import argparse
from multiprocessing import Pool, Manager
requests.packages.urllib3.disable_warnings()

from loguru import logger
logger.remove()
handler_id = logger.add(sys.stderr, level="DEBUG")

# Dictionary for assigning values based on parameter type
payload_array = {"string": "1", "boolean": "true", "integer": "1", "array": "1", "number": "1", "object": ""}

# Payload for POST/PUT requests
json_payload = """{
  "code": "string",
  "createTime": "2021-02-05T10:34:37.691Z",
  "delFlag": "string",
  "deptId": 0,
  "fullName": "string",
  "fullPathCode": "string",
  "fullPathName": "string",
  "isVirtual": true,
  "name": "string",
  "outCode": "string",
  "outParentCode": "string",
  "parentCode": "string",
  "parentId": 0,
  "parentName": "string",
  "sort": 0,
  "updateTime": "2021-02-05T10:34:37.691Z"
}"""

def banner():
    logger.info(r'''
                                              _                _    
 _____      ____ _  __ _  __ _  ___ _ __     | |__   __ _  ___| | __
/ __\ \ /\ / / _` |/ _` |/ _` |/ _ \ '__|____| '_ \ / _` |/ __| |/ /
\__ \\ V  V / (_| | (_| | (_| |  __/ | |_____| | | | (_| | (__|   < 
|___/ \_/\_/ \__,_|\__, |\__, |\___|_|       |_| |_|\__,_|\___|_|\_\\
                   |___/ |___/                                      
                                                            by Elhussain
    
    python swagger.py -h
    ''')

proxy = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# Custom headers with a custom User-Agent
headers = {
    "User-Agent": "Mozilla/5.0",
    "Authorization": "Bearer ADD-Token-Here"
}

def build_url(domain, basePath, path):
    """Constructs the complete URL by properly joining domain, basePath, and path."""
    # Ensure basePath has a leading slash but no trailing slash
    if not basePath.startswith('/'):
        basePath = '/' + basePath
    if basePath.endswith('/'):
        basePath = basePath.rstrip('/')
    
    # Ensure path has a leading slash
    if not path.startswith('/'):
        path = '/' + path
    
    return urljoin(domain + basePath, path)

def replace_path_params(path, param_map):
    """Replace placeholders like {userId}, {changeType}, etc., in the URL with actual values."""
    placeholders = re.findall(r"\{(.*?)\}", path)
    
    # Replace each placeholder with the corresponding value from param_map or default value
    for placeholder in placeholders:
        if placeholder not in param_map:
            logger.error(f"Missing value for placeholder: {placeholder}. Using default value '1'.")
            param_map[placeholder] = '1'  # Assign a default value if it's missing
        path = path.replace(f"{{{placeholder}}}", param_map[placeholder])
    
    return path

def handle_post_put(domain, basePath, path, method, global_data, summary, param_num):
    """Handle POST/PUT requests."""
    try:
        param_map = {}
        path = replace_path_params(path, param_map)

        req_url = build_url(domain, basePath, path)
        logger.debug(f"Sending {method.upper()} request to {req_url}")
        logger.debug(f"Headers: {headers}")

        req_payload = json_payload

        if method == 'post':
            req = requests.post(url=req_url, data=req_payload, timeout=5, verify=False, proxies=proxy, headers=headers.copy())
        else:
            req = requests.put(url=req_url, data=req_payload, timeout=5, verify=False, proxies=proxy, headers=headers.copy())

        logger.debug(f"Response Status Code: {req.status_code}")
        logger.debug(f"Response Body: {req.text}")

        hhh = [req_url, summary, path, method, req_url, param_num, req_payload, req.status_code, req.text]
        global_data.put(hhh)
    except Exception as e:
        logger.error(f"Error in handle_post_put: {e}")

def handle_get_delete(domain, basePath, path, method, method_details, global_data, summary, param_num):
    """Handle GET/DELETE requests."""
    try:
        param_map = {}
        path = replace_path_params(path, param_map)

        querystring = ""

        if "parameters" in method_details:
            for param in method_details['parameters']:
                p_name = param['name']
                p_type = param.get('schema', {}).get('type', 'string')
                param_map[p_name] = payload_array.get(p_type, '1')

            querystring = '&'.join([f"{k}={v}" for k, v in param_map.items()])

        req_url = build_url(domain, basePath, path)
        if querystring:
            req_url += '?' + querystring

        logger.debug(f"Sending {method.upper()} request to {req_url}")
        logger.debug(f"Headers: {headers}")

        if method == 'get':
            req = requests.get(url=req_url, timeout=5, verify=False, proxies=proxy, headers=headers.copy())
        else:
            req = requests.delete(url=req_url, timeout=5, verify=False, proxies=proxy, headers=headers.copy())

        logger.debug(f"Response Status Code: {req.status_code}")
        logger.debug(f"Response Body: {req.text}")

        hhh = [req_url, summary, path, method, req_url, param_num, param_map, req.status_code, req.text]
        global_data.put(hhh)
    except Exception as e:
        logger.error(f"Error in handle_get_delete: {e}")

def run(file_path):
    try:
        with open(file_path) as f:
            swagger_data = json.load(f)

        # Extract base URL if available
        basePath = '/'
        domain = 'https://ipads.adnoc.ae/api'  # Replace with the appropriate domain

        if 'servers' in swagger_data and isinstance(swagger_data['servers'], list):
            basePath = swagger_data['servers'][0]['url']

        if 'paths' not in swagger_data:
            logger.error("[!] Error: No paths found in Swagger file")
            return

        paths = swagger_data['paths']
        logger.info(f"[+] Found {len(paths)} paths in Swagger file")

        manager = Manager()
        global_data = manager.Queue()

        for path, methods in paths.items():
            for method, method_details in methods.items():
                logger.info(f"Processing {method.upper()} {path}")
                summary = method_details.get('summary', path)
                param_num = str(method_details).count("'in':")

                if method in ['post', 'put']:
                    handle_post_put(domain, basePath, path, method, global_data, summary, param_num)
                elif method in ['get', 'delete']:
                    handle_get_delete(domain, basePath, path, method, method_details, global_data, summary, param_num)
                else:
                    logger.error(f"Unknown method: {method}")

        output_to_csv(global_data)

    except json.JSONDecodeError:
        logger.error("Failed to parse the Swagger JSON file. Please check the format.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

def output_to_csv(global_data):
    with open('swagger.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["API Doc URL", "Summary", "Path", "Method", "Query URL", "Number of Params", "Data", "Status Code", "Response"])
        while not global_data.empty():
            writer.writerow(global_data.get())

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", dest='url_file', help="Swagger JSON file containing API documentation")
    parser.add_argument("-t", "--token", dest='auth_token', help="Bearer token for authorization")
    args = parser.parse_args()

    logger.add("file.log", format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}")
    banner()
    
    if args.auth_token:
        headers["Authorization"] = f"Bearer {args.auth_token}"
    
    if args.url_file:
        run(args.url_file)
    else:
        logger.error("Please provide a Swagger JSON file using -f option.")
