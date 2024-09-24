#!/usr/bin/env python3

import argparse
import requests
import subprocess
import os
import shodan
import dns.resolver
from bs4 import BeautifulSoup
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Argument parser
def create_parser():
    parser = argparse.ArgumentParser(description="Piga Hacks - Recon Tool")
    
    # Recon Commands
    parser.add_argument("-s", "--subdomains", help="Scan for subdomains")
    parser.add_argument("-t", "--tech", help="Find technologies of a domain")
    parser.add_argument("-d", "--dns", help="Scan a list of domains for DNS records")
    parser.add_argument("-sh", "--securityheaders", help="Scan for security headers")
    parser.add_argument("-sc", "--statuscode", help="Get HTTP status code of a domain")
    parser.add_argument("-shodan", "--shodan", help="Recon with Shodan")
    parser.add_argument("--shodan-api", help="Shodan API Key")
    
    # Vulnerability Scanning
    parser.add_argument("-xss", "--xss_scan", help="Scan for XSS vulnerabilities")
    parser.add_argument("-sqli", "--sqli_scan", help="Scan for SQLi vulnerabilities")
    
    # Crawler
    parser.add_argument("-w", "--waybackurls", help="Scan for Wayback URLs")
    parser.add_argument("-wc", "--webcrawler", help="Crawl a website for URLs and JS files")
    
    # Port Scanning
    parser.add_argument("-n", "--nmap", help="Scan a target with nmap")
    parser.add_argument("-cidr", "--cidr_notation", help="Scan IP range using CIDR notation")
    parser.add_argument("-ps", "--ports", help="Port numbers to scan")
    
    # Concurrency & Threads
    parser.add_argument("-th", "--threads", type=int, default=25, help="Number of threads (default 25)")
    
    return parser

# DNS Query Function (Threaded)
def dns_query(domain):
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"{domain} A Record: {rdata}")
    except dns.exception.DNSException as e:
        print(f"Error resolving {domain}: {e}")

# Shodan Lookup (Threaded)
def shodan_lookup(api_key, domain):
    api = shodan.Shodan(api_key)
    try:
        host = api.host(domain)
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'n/a')}")
        print(f"Operating System: {host.get('os', 'n/a')}")
        for item in host['data']:
            print(f"Port: {item['port']}, Banner: {item['data']}")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")

# HTTP Status Code Check (Threaded)
def check_status_code(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        print(f"HTTP Status Code for {domain}: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error fetching status code for {domain}: {e}")

# XSS Vulnerability Scan
def scan_xss(target_url):
    xss_payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
    for payload in xss_payloads:
        try:
            response = requests.get(f"{target_url}?param={payload}", timeout=5)
            if payload in response.text:
                print(f"[+] XSS Vulnerability found on {target_url}")
        except requests.RequestException as e:
            print(f"Error checking XSS on {target_url}: {e}")

# SQLi Vulnerability Scan
def scan_sqli(target_url):
    sqli_payloads = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT 1,2,3 -- "]
    for payload in sqli_payloads:
        try:
            response = requests.get(f"{target_url}?param={payload}", timeout=5)
            if "SQL" in response.text or "syntax" in response.text:
                print(f"[+] SQLi Vulnerability found on {target_url}")
        except requests.RequestException as e:
            print(f"Error checking SQLi on {target_url}: {e}")

# Wayback URLs (Threaded)
def get_wayback_urls(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=txt&fl=original&collapse=urlkey"
    try:
        response = requests.get(url, timeout=5)
        urls = response.text.splitlines()
        print(f"Found {len(urls)} Wayback URLs for {domain}:")
        for u in urls:
            print(u)
    except requests.RequestException as e:
        print(f"Error retrieving Wayback URLs: {e}")

# Web Crawler - Extract URLs and JavaScript files
def web_crawler(domain):
    try:
        response = requests.get(domain, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        urls = [a['href'] for a in soup.find_all('a', href=True)]
        js_files = [script['src'] for script in soup.find_all('script', src=True)]
        print(f"Found {len(urls)} URLs on {domain}:")
        for url in urls:
            print(url)
        print(f"Found {len(js_files)} JavaScript files on {domain}:")
        for js in js_files:
            print(js)
    except requests.RequestException as e:
        print(f"Error crawling {domain}: {e}")

# Running nmap (Threaded)
def run_nmap(target, ports):
    nmap_command = f"nmap -p {ports} {target}"
    try:
        subprocess.run(nmap_command, shell=True)
    except Exception as e:
        print(f"Error running nmap: {e}")

# Scan a CIDR Range (Threaded)
def scan_cidr(cidr_range):
    nmap_command = f"nmap -sP {cidr_range}"
    try:
        subprocess.run(nmap_command, shell=True)
    except Exception as e:
        print(f"Error running CIDR scan: {e}")

# Threading logic for tasks
def threaded_task_executor(function, task_list, max_threads):
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {executor.submit(function, task): task for task in task_list}
        for future in as_completed(futures):
            try:
                future.result()  # Get the result of the function
            except Exception as exc:
                print(f"Error occurred: {exc}")

# Main function
def main():
    parser = create_parser()
    args = parser.parse_args()

    # Thread pool size (concurrency)
    thread_count = args.threads

    # DNS Scan - Running in threads
    if args.dns:
        with open(args.dns, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
        print(f"Running DNS Queries on {len(domains)} domains...")
        threaded_task_executor(dns_query, domains, thread_count)

    # Shodan Lookup - Single target
    if args.shodan and args.shodan_api:
        shodan_lookup(args.shodan_api, args.shodan)

    # HTTP Status Code Check - Running in threads
    if args.statuscode:
        with open(args.statuscode, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
        print(f"Checking status codes for {len(domains)} domains...")
        threaded_task_executor(check_status_code, domains, thread_count)

    # XSS Vulnerability Scan
    if args.xss_scan:
        scan_xss(args.xss_scan)

    # SQLi Vulnerability Scan
    if args.sqli_scan:
        scan_sqli(args.sqli_scan)

    # Wayback URLs - Running in threads
    if args.waybackurls:
        with open(args.waybackurls, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
        print(f"Fetching Wayback URLs for {len(domains)} domains...")
        threaded_task_executor(get_wayback_urls, domains, thread_count)

    # Web Crawler - Crawling websites for URLs and JS files
    if args.webcrawler:
        web_crawler(args.webcrawler)

    # Nmap Scan - Running in threads
    if args.nmap and args.ports:
        with open(args.nmap, 'r') as f:
            targets = [line.strip() for line in f.readlines()]
        print(f"Running Nmap scans on {len(targets)} targets...")
        threaded_task_executor(lambda target: run_nmap(target, args.ports), targets, thread_count)

    # CIDR Range Scanning
    if args.cidr_notation:
        scan_cidr(args.cidr_notation)

if __name__ == "__main__":
    main()
