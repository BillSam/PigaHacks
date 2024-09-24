#!/usr/bin/env python3

import argparse
import requests
import subprocess
import os
import shodan
import dns.resolver
from bs4 import BeautifulSoup
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Function to print the banner
def print_banner():
    banner = r"""
  ____  _             
 |  _ \(_) __ _  _ __  
 | |_) | |/ _` || '_ \ 
 |  __/| | (_| || |_ ||
 |_|   |_|\__,_||_| |_|
             |_| 
   P I G A  H A C K S   
"""
    print("\033[1;36m" + banner + "\033[0m")  # Cyan color for the banner

# Status printing with colors
def print_status(message):
    print(f"\033[94m[INFO] {message}\033[0m")  # Blue text for information

def print_success(message):
    print(f"\033[92m[SUCCESS] {message}\033[0m")  # Green text for success

def print_error(message):
    print(f"\033[91m[ERROR] {message}\033[0m")  # Red text for errors

def print_warning(message):
    print(f"\033[93m[WARNING] {message}\033[0m")  # Yellow text for warnings

# Argument parser
def create_parser():
    parser = argparse.ArgumentParser(description="Piga Hacks - Recon Tool")
    
    # Recon Commands
    parser.add_argument("-s", "--subdomains", help="Scan for subdomains")
    parser.add_argument("-amass", "--amass_scan", help="Perform subdomain enumeration using Amass")
    parser.add_argument("-crt", "--crt_scan", help="Get SSL certificates from crt.sh for a domain")
    parser.add_argument("-t", "--tech", help="Find technologies of a domain")
    parser.add_argument("-d", "--dns", help="Scan a list of domains for DNS records")
    parser.add_argument("-sh", "--securityheaders", help="Scan for security headers")
    parser.add_argument("-sc", "--statuscode", help="Get HTTP status code of a domain")
    parser.add_argument("-shodan", "--shodan", help="Recon with Shodan")
    parser.add_argument("--shodan-api", help="Shodan API Key", required='--shodan' in sys.argv)
    
    # Vulnerability Scanning
    parser.add_argument("-xss", "--xss_scan", help="Scan for XSS vulnerabilities")
    parser.add_argument("-sqli", "--sqli_scan", help="Scan for SQLi vulnerabilities")
    parser.add_argument("-or", "--open_redirect", help="Scan for Open Redirect vulnerabilities")
    parser.add_argument("-cj", "--clickjack", help="Scan for Clickjacking vulnerability")
    
    # Crawler
    parser.add_argument("-w", "--waybackurls", help="Scan for Wayback URLs")
    parser.add_argument("-wc", "--webcrawler", help="Crawl a website for URLs and JS files")
    
    # Port Scanning
    parser.add_argument("-n", "--nmap", help="Scan a target with nmap")
    parser.add_argument("-cidr", "--cidr_notation", help="Scan IP range using CIDR notation")
    parser.add_argument("-ps", "--ports", help="Port numbers to scan", required='--nmap' in sys.argv)
    
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
        print_error(f"Error resolving {domain}: {e}")

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
        print_error(f"Shodan API Error: {e}")

# HTTP Status Code Check (Threaded)
def check_status_code(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        print(f"HTTP Status Code for {domain}: {response.status_code}")
    except requests.RequestException as e:
        print_error(f"Error fetching status code for {domain}: {e}")

# Security Header Scan
def scan_security_headers(domain):
    try:
        response = requests.get(domain, timeout=5)
        headers = response.headers
        print(f"Security Headers for {domain}:")
        security_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
        for header in security_headers:
            if header in headers:
                print_success(f"{header}: {headers[header]}")
            else:
                print_warning(f"{header} not set")
    except requests.RequestException as e:
        print_error(f"Error scanning security headers for {domain}: {e}")

# XSS Vulnerability Scan
def scan_xss(target_url):
    xss_payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
    for payload in xss_payloads:
        try:
            response = requests.get(f"{target_url}?param={payload}", timeout=5)
            if payload in response.text:
                print_success(f"[+] XSS Vulnerability found on {target_url}")
        except requests.RequestException as e:
            print_error(f"Error checking XSS on {target_url}: {e}")

# SQLi Vulnerability Scan
def scan_sqli(target_url):
    sqli_payloads = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT 1,2,3 -- "]
    for payload in sqli_payloads:
        try:
            response = requests.get(f"{target_url}?param={payload}", timeout=5)
            if "SQL" in response.text or "syntax" in response.text:
                print_success(f"[+] SQLi Vulnerability found on {target_url}")
        except requests.RequestException as e:
            print_error(f"Error checking SQLi on {target_url}: {e}")

# Open Redirect Scan
def scan_open_redirect(target_url):
    payloads = ["/?url=https://evil.com", "/redirect?url=https://evil.com"]
    for payload in payloads:
        try:
            response = requests.get(f"{target_url}{payload}", allow_redirects=False, timeout=5)
            if response.status_code == 302 or response.status_code == 301:
                print_success(f"[+] Open Redirect Vulnerability found on {target_url}")
        except requests.RequestException as e:
            print_error(f"Error checking open redirect on {target_url}: {e}")

# Clickjacking Scan
def scan_clickjacking(domain):
    try:
        response = requests.get(domain, timeout=5)
        if 'X-Frame-Options' not in response.headers:
            print_warning(f"[!] Clickjacking vulnerability likely on {domain}. No X-Frame-Options set!")
        else:
            print_success(f"X-Frame-Options is set on {domain}")
    except requests.RequestException as e:
        print_error(f"Error checking clickjacking for {domain}: {e}")

# Wayback URLs and gau integration (Threaded)
def get_wayback_urls_and_gau(domain):
    urls = set()  # Use a set to avoid duplicates

    # Get URLs from gau
    try:
        print_status(f"Fetching URLs using gau for {domain}...")
        gau_output = subprocess.run(f"gau {domain}", shell=True, capture_output=True, text=True)
        if gau_output.returncode == 0:
            gau_urls = gau_output.stdout.splitlines()
            urls.update(gau_urls)
            print(f"Found {len(gau_urls)} URLs using gau for {domain}")
        else:
            print_error(f"Error fetching URLs with gau for {domain}: {gau_output.stderr}")
    except Exception as e:
        print_error(f"Error executing gau: {e}")

    # Get URLs from Wayback Machine
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=txt&fl=original&collapse=urlkey"
    try:
        print_status(f"Fetching Wayback Machine URLs for {domain}...")
        response = requests.get(wayback_url, timeout=5)
        print(response.content)
        wayback_urls = response.text.splitlines()
        urls.update(wayback_urls)
        print(f"Found {len(wayback_urls)} Wayback URLs for {domain}")
    except requests.RequestException as e:
        print_error(f"Error retrieving Wayback URLs: {e}")

    # Print all collected URLs
    if urls:
        print(f"Total unique URLs collected for {domain}: {len(urls)}")
        for url in urls:
            print(url)
    else:
        print_warning(f"No URLs found for {domain}")


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
        print_error(f"Error crawling {domain}: {e}")

# crt.sh SSL Certificate Scan
def crt_sh_scan(domain):
    crt_url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(crt_url, timeout=5)
        if response.status_code == 200:
            certs = response.json()
            print(f"Found {len(certs)} certificates for {domain}:")
            for cert in certs:
                print(f"Common Name: {cert['common_name']}, Issuer: {cert['issuer_name']}, Valid From: {cert['not_before']}")
        else:
            print_error(f"crt.sh returned status code {response.status_code}")
    except requests.RequestException as e:
        print_error(f"Error fetching SSL certificates from crt.sh: {e}")

# Amass Subdomain Enumeration
def amass_subdomain_scan(domain):
    try:
        subprocess.run(f"amass enum -d {domain} -o amass_output.txt", shell=True, check=True)
        with open("amass_output.txt", 'r') as f:
            subdomains = f.readlines()
        print(f"Amass found {len(subdomains)} subdomains for {domain}:")
        for subdomain in subdomains:
            print(subdomain.strip())
    except subprocess.CalledProcessError as e:
        print_error(f"Error running Amass: {e}")

# Running nmap (Threaded)
def run_nmap(target, ports):
    nmap_command = f"nmap -sV -O -p {ports} {target}"  # Adding OS detection and service version scan
    try:
        subprocess.run(nmap_command, shell=True)
    except Exception as e:
        print_error(f"Error running nmap: {e}")

# Scan a CIDR Range (Threaded)
def scan_cidr(cidr_range):
    nmap_command = f"nmap -sP {cidr_range}"
    try:
        subprocess.run(nmap_command, shell=True)
    except Exception as e:
        print_error(f"Error running CIDR scan: {e}")

# Threading logic for tasks
def threaded_task_executor(function, task_list, max_threads):
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {executor.submit(function, task): task for task in task_list}
        for future in as_completed(futures):
            try:
                future.result()  # Get the result of the function
            except Exception as exc:
                print_error(f"Error occurred: {exc}")

# Main function
def main():
    # Print the banner at the start
    print_banner()

    parser = create_parser()
    args = parser.parse_args()

    # Thread pool size (concurrency)
    thread_count = args.threads

    # DNS Scan - Running in threads
    if args.dns:
        print_status(f"Starting DNS queries for domains listed in {args.dns}")
        with open(args.dns, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
        print_status(f"Running DNS Queries on {len(domains)} domains with {thread_count} threads...")
        threaded_task_executor(dns_query, domains, thread_count)
        print_success("DNS queries completed.")

    # Shodan Lookup - Single target
    if args.shodan and args.shodan_api:
        print_status(f"Starting Shodan lookup for {args.shodan}")
        shodan_lookup(args.shodan_api, args.shodan)
        print_success("Shodan lookup completed.")

    # HTTP Status Code Check - Running in threads
    if args.statuscode:
        print_status(f"Checking HTTP status codes for domains listed in {args.statuscode}")
        with open(args.statuscode, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
        print_status(f"Checking status codes for {len(domains)} domains with {thread_count} threads...")
        threaded_task_executor(check_status_code, domains, thread_count)
        print_success("HTTP status code check completed.")

    # Security Header Scan
    if args.securityheaders:
        print_status(f"Scanning security headers for {args.securityheaders}")
        scan_security_headers(args.securityheaders)
        print_success("Security header scan completed.")

    # XSS Vulnerability Scan
    if args.xss_scan:
        print_status(f"Starting XSS scan for {args.xss_scan}")
        scan_xss(args.xss_scan)
        print_success("XSS scan completed.")

    # SQLi Vulnerability Scan
    if args.sqli_scan:
        print_status(f"Starting SQLi scan for {args.sqli_scan}")
        scan_sqli(args.sqli_scan)
        print_success("SQLi scan completed.")

    # Open Redirect Scan
    if args.open_redirect:
        print_status(f"Starting Open Redirect scan for {args.open_redirect}")
        scan_open_redirect(args.open_redirect)
        print_success("Open Redirect scan completed.")

    # Clickjacking Scan
    if args.clickjack:
        print_status(f"Checking for Clickjacking vulnerabilities on {args.clickjack}")
        scan_clickjacking(args.clickjack)
        print_success("Clickjacking check completed.")

    # crt.sh SSL Certificate Scan
    if args.crt_scan:
        print_status(f"Fetching SSL certificates from crt.sh for {args.crt_scan}")
        crt_sh_scan(args.crt_scan)
        print_success("crt.sh scan completed.")

    # Amass Subdomain Enumeration
    if args.amass_scan:
        print_status(f"Starting Amass subdomain enumeration for {args.amass_scan}")
        amass_subdomain_scan(args.amass_scan)
        print_success("Amass subdomain enumeration completed.")

    # Wayback URLs - Running in threads
    if args.waybackurls:
        print_status(f"Fetching Wayback URLs for domains listed in {args.waybackurls}")
        with open(args.waybackurls, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
        print_status(f"Fetching Wayback URLs for {len(domains)} domains with {thread_count} threads...")
        threaded_task_executor(get_wayback_urls_and_gau, domains, thread_count)
        print_success("Wayback URL fetching completed.")

    # Web Crawler - Crawling websites for URLs and JS files
    if args.webcrawler:
        print_status(f"Crawling {args.webcrawler} for URLs and JavaScript files")
        web_crawler(args.webcrawler)
        print_success("Web crawling completed.")

    # Nmap Scan - Running in threads
    if args.nmap and args.ports:
        print_status(f"Starting Nmap scan for targets listed in {args.nmap}")
        with open(args.nmap, 'r') as f:
            targets = [line.strip() for line in f.readlines()]
        print_status(f"Running Nmap scans on {len(targets)} targets with {thread_count} threads...")
        threaded_task_executor(lambda target: run_nmap(target, args.ports), targets, thread_count)
        print_success("Nmap scan completed.")

    # CIDR Range Scanning
    if args.cidr_notation:
        print_status(f"Starting CIDR range scan for {args.cidr_notation}")
        scan_cidr(args.cidr_notation)
        print_success("CIDR range scan completed.")

if __name__ == "__main__":
    main()
