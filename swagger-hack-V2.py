#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
import json, os, re
import time, sys
from urllib.parse import urlparse
import requests
import csv
import argparse
from multiprocessing import Pool, Manager
from loguru import logger
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

requests.packages.urllib3.disable_warnings()

logger.remove()
handler_id = logger.add(sys.stderr, level="DEBUG")  # Set log level

payload_array = {"string": "1", "boolean": "true", "integer": "1", "array": "1", "number": "1", "object": ""}  # Assign values based on parameter type

# Post type data payload
json_payload = {
    "code": "string",
    "createTime": "2021-02-05T10:34:37.691Z",
    "delFlag": "string",
    "deptId": 0,
    "fullName": "string",
    "fullPathCode": "string",
    "fullPathName": "string",
    "isVirtual": True,
    "name": "string",
    "outCode": "string",
    "outParentCode": "string",
    "parentCode": "string",
    "parentId": 0,
    "parentName": "string",
    "sort": 0,
    "updateTime": "2021-02-05T10:34:37.691Z"
}

def banner():
    logger.info(r'''
                                              _                _    
 _____      ____ _  __ _  __ _  ___ _ __     | |__   __ _  ___| | __
/ __\ \ /\ / / _` |/ _` |/ _` |/ _ \ '__|____| '_ \ / _` |/ __| |/ /
\__ \ V  V / (_| | (_| | (_| |  __/ | |_____| | | | (_| | (__|   < 
|___/ \_/\_/ \__,_|\__,_|\__, |\___|_|       |_| |_|\__,_|\___|_|\_\
                   |___/ |___/                                      
                                                            by jayus
    ''')

def go_docs_from_file(file_path, global_data):
    try:
        logger.debug(f"Reading Swagger documentation from file: {file_path}")
        with open(file_path, 'r') as f:
            res = json.load(f)
        
        basePath = ''
        if "basePath" in res.keys():
            basePath = res['basePath']  # e.g., /santaba/rest
        elif "servers" in res.keys() and len(res["servers"]) > 0:
            basePath = res["servers"][0]['url']
        else:
            basePath = ''
        
        paths = res.get('paths', {})
        path_num = len(paths)
        logger.info(f"[+] {file_path} has {path_num} paths")
        
        if path_num == 0:
            logger.warning("No paths found in the Swagger documentation.")
            return
        
        domain = basePath if basePath.startswith('http') else "http://example.com"  # Placeholder domain since this is from a file
        
        for path in paths:  # path string
            res_path = path
            logger.debug(f"Testing on {file_path} => {path}")
            try:
                for method in paths[res_path]:  # get/post/put strings
                    path = res_path
                    text = str(paths[path][method])
                    param_num = text.count("'in':")
                    try:
                        summary = paths[path][method].get('summary', path)
                    except Exception as e:
                        logger.error(f"Error getting summary: {e}")
                        summary = path
                    
                    headers = {'Content-Type': 'application/json'}
                    if method in ['post', 'put']:
                        logger.debug(f"Attempting {method.upper()} request to {basePath + path if basePath.startswith('http') else domain + path} with payload: {json_payload}")
                        if "'in': 'body'" in text:
                            try:
                                req = requests.request(method=method, url=basePath + path if basePath.startswith('http') else domain + path, headers=headers, json=json_payload, timeout=5, verify=False, proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})
                                logger.debug(f"{method.upper()} request successful: Status Code: {req.status_code}")
                            except requests.exceptions.RequestException as e:
                                logger.error(f"{method.upper()} request failed: {e}")
                                req = None
                            hhh = [file_path, summary, path, method, basePath + path if basePath.startswith('http') else domain + path, param_num, json_payload, req.status_code if req else 'N/A', req.text if req else 'N/A']
                        elif "'in': 'path'" in text:
                            param_map = {}
                            parameters = paths[path][method].get('parameters', [])
                            for param in parameters:
                                p_type = param.get('type') or param.get("schema", {}).get("type", '')
                                p_name = param['name']
                                param_map[p_name] = payload_array.get(p_type, "default")
                            if "{" in path:
                                tmps = re.findall(r"\{[^\}]*\}", path)
                                for tmp in tmps:
                                    path = path.replace(tmp, param_map[tmp[1:-1]])
                            hhh = [file_path, summary, path, method, basePath + path if basePath.startswith('http') else domain + path, param_num, json_payload, "N/A", "N/A"]
                        elif "'in': 'query'" in text:
                            param_map = {}
                            parameters = paths[path][method].get('parameters', [])
                            for param in parameters:
                                p_type = param.get('type') or param.get("schema", {}).get("type", '')
                                p_name = param['name']
                                param_map[p_name] = payload_array.get(p_type, "default")
                            hhh = [file_path, summary, path, method, domain + basePath + path, param_num, param_map, "N/A", "N/A"]
                        else:
                            hhh = [file_path, summary, path, method, domain + basePath + path, param_num, json_payload, "N/A", "N/A"]
                        global_data.put(hhh)
                    elif method in ["get", "delete"]:
                        querystring = ""
                        param_map = {}
                        if "parameters" in paths[path][method].keys():  # Has parameters
                            parameters = paths[path][method].get('parameters', [])
                            for param in parameters:
                                p_type = param.get('type') or param.get("schema", {}).get("type", '')
                                p_name = param['name']
                                param_map[p_name] = payload_array.get(p_type, "default")
                            for key in param_map.keys():
                                querystring += f"{key}={param_map[key]}&"
                            if "{" in path:
                                tmps = re.findall(r"\{[^\}]*\}", path)
                                for tmp in tmps:
                                    path = path.replace(tmp, param_map[tmp[1:-1]])
                            query_url = basePath + path + '/?' + querystring[:-1] if basePath.startswith('http') else domain + path + '/?' + querystring[:-1]
                            try:
                                req = requests.request(method=method, url=query_url, headers=headers, timeout=5, verify=False, proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})
                                logger.debug(f"{method.upper()} request successful: Status Code: {req.status_code}")
                            except requests.exceptions.RequestException as e:
                                logger.error(f"{method.upper()} request failed: {e}")
                                req = None
                            hhh = [file_path, summary, path, method, query_url, param_num, param_map, req.status_code if req else 'N/A', req.text if req else 'N/A']
                        else:  # No parameters
                            query_url = basePath + path if basePath.startswith('http') else domain + path
                            hhh = [file_path, summary, path, method, query_url, param_num, param_map, "N/A", "N/A"]
                        global_data.put(hhh)
                    else:
                        logger.error(f"[!] Encountered unhandled request method: {method}")
            except Exception as e:
                logger.error(f"Exception during processing path {path}: {e}")
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        logger.error(f"Exception in go_docs_from_file: {e}")

def run_pool(urls, is_file=False):
    logger.debug("Starting multiprocessing pool")
    p = Pool(8)
    manager = Manager()
    q = manager.Queue()
    if is_file:
        for url in urls:
            url = url.strip()
            p.apply_async(go_docs_from_file, args=(url, q), error_callback=print_error)
    else:
        for url in urls:
            url = url.strip()
            param = [url, q]
            p.apply_async(run, args=(param,), error_callback=print_error)
    p.close()
    p.join()
    output_to_csv(q)

def output_to_csv(global_data):
    logger.debug("Writing output to CSV")
    with open('swagger.csv', 'w', newline='', encoding='utf-8') as f:  # Write to CSV
        writer = csv.writer(f)
        try:
            writer.writerow(["api-doc-url", "summary", "path", "method", "query_url", "num of params", "data", "status_code", "response"])
        except Exception as e:
            logger.error(f"Error writing CSV header: {e}")
        while not global_data.empty():
            writer.writerow(global_data.get())

def print_error(value):
    logger.error(f"Error in process pool, reason: {value}")

def run(data):
    url = data[0]
    q = data[1]
    url_type = check(url)
    if url_type == 0:
        logger.error("[!] Error")
        exit()
    elif url_type == 1:
        logger.success(f"working on {url} type: source")
        go_source(url, q)
    elif url_type == 2:
        logger.success(f"working on {url} type: api-docs")
        go_docs(url, q)
    else:
        logger.success(f"working on {url} type: html")
        go_html(url, q)

def go_html(urlq, q):
    logger.debug(f"Handling HTML content for URL: {urlq}")
    pass

def go_source(url, q):
    logger.debug(f"Handling source content for URL: {url}")
    pass

if __name__ == '__main__':
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest='target_url', help="resource address or API documentation address or swagger homepage address")
    parser.add_argument("-f", "--file", dest='url_file', help="batch test")
    args = parser.parse_args()

    logger.add("file.log", format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}")
    
    if args.target_url:
        run_pool([args.target_url])
    elif args.url_file:
        run_pool([args.url_file], is_file=True)
