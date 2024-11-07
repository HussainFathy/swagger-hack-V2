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
                                                            by 0xSphinx
    
    python swagger.py -h
    ''')

proxy = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# Custom headers with a custom User-Agent
headers = {
    "User-Agent": "Mozilla/5.0"
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

def check(url):
    """Check if the URL points to a Swagger homepage, API doc, or resource."""
    try:
        res = requests.get(url=url, timeout=5, verify=False, proxies=proxy, headers=headers)
        if "<html" in res.text:
            logger.debug("[+] The input URL is a Swagger homepage, parsing API documentation URL")
            return 3  # HTML
        elif "\"parameters\"" in res.text:
            logger.debug("[+] The input URL is an API documentation URL, constructing request payloads")
            return 2  # API doc
        elif "\"location\"" in res.text:
            logger.debug("[+] The input URL is a resource URL, parsing API documentation URL")
            return 1  # Resource
    except KeyboardInterrupt:
        print("Process interrupted")
    except Exception as e:
        print(e)
        return 0

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

def go_docs(url, global_data):
    """Parse API documentation and send requests based on the methods found."""
    try:
        domain = urlparse(url)
        domain = domain.scheme + "://" + domain.netloc

        try:
            res = requests.get(url=url, timeout=5, verify=False, proxies=proxy, headers=headers)
            res.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to fetch the Swagger JSON: {e}")
            return

        res_json = res.json()

        # Handle OpenAPI 3.0 servers
        basePath = '/'
        if "servers" in res_json and isinstance(res_json['servers'], list):
            basePath = res_json['servers'][0]['url']  # Use the first server URL

        paths = res_json.get('paths', {})
        logger.info(f"[+] {url} has {len(paths)} paths")

        for path, methods in paths.items():
            if isinstance(methods, dict):
                logger.debug(f"Testing path {path}")
                
                for method, method_details in methods.items():
                    summary = method_details.get('summary', path)
                    param_num = str(method_details).count("'in':")

                    logger.debug(f"Method: {method}, Summary: {summary}")

                    if method in ['post', 'put']:
                        handle_post_put(domain, basePath, path, method, global_data, summary, param_num)
                    elif method in ['get', 'delete']:
                        handle_get_delete(domain, basePath, path, method, method_details, global_data, summary, param_num)
                    else:
                        logger.error(f"Unknown method: {method}")
    except Exception as e:
        logger.error(f"Error in go_docs: {e}")

def handle_post_put(domain, basePath, path, method, global_data, summary, param_num):
    """Handle POST/PUT requests."""
    try:
        param_map = {}
        path = replace_path_params(path, param_map)

        req_url = build_url(domain, basePath, path)
        logger.debug(f"Sending {method.upper()} request to {req_url}")

        req_payload = json_payload

        if method == 'post':
            req = requests.post(url=req_url, data=req_payload, timeout=5, verify=False, proxies=proxy, headers=headers)
        else:
            req = requests.put(url=req_url, data=req_payload, timeout=5, verify=False, proxies=proxy, headers=headers)

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

        if method == 'get':
            req = requests.get(url=req_url, timeout=5, verify=False, proxies=proxy, headers=headers)
        else:
            req = requests.delete(url=req_url, timeout=5, verify=False, proxies=proxy, headers=headers)

        logger.debug(f"Response Status Code: {req.status_code}")
        logger.debug(f"Response Body: {req.text}")

        hhh = [req_url, summary, path, method, req_url, param_num, param_map, req.status_code, req.text]
        global_data.put(hhh)
    except Exception as e:
        logger.error(f"Error in handle_get_delete: {e}")

def run(data):
    url = data[0]
    q = data[1]
    url_type = check(url)
    if url_type == 0:
        logger.error("[!] Error")
        exit()
    elif url_type == 1:
        logger.success(f"Working on {url}, type: resource")
        go_source(url)
    elif url_type == 2:
        logger.success(f"Working on {url}, type: API documentation")
        go_docs(url, q)
    else:
        logger.success(f"Skipping HTML page: {url}")

def run_pool(urls):
    p = Pool(8)
    manager = Manager()
    q = manager.Queue()
    for url in urls:
        url = url.strip()
        param = [url, q]
        p.apply_async(run, args=(param,))
    p.close()
    p.join()
    output_to_csv(q)

def output_to_csv(global_data):
    with open('swagger.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["API Doc URL", "Summary", "Path", "Method", "Query URL", "Number of Params", "Data", "Status Code", "Response"])
        while not global_data.empty():
            writer.writerow(global_data.get())

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest='target_url', help="Resource URL, API documentation URL, or Swagger homepage URL")
    parser.add_argument("-f", "--file", dest='url_file', help="File containing multiple URLs for batch testing")
    args = parser.parse_args()

    logger.add("file.log", format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}")
    banner()
    
    if args.target_url:
        run_pool([args.target_url])
    elif args.url_file:
        with open(args.url_file, 'r') as f:
            urls = f.readlines()
        run_pool(urls)
