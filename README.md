# PigaHacks
# Piga Hacks

**Piga Hacks** is a powerful, multi-threaded reconnaissance and vulnerability scanning tool designed for penetration testers, security researchers, and ethical hackers. It allows for efficient and fast information gathering, web crawling, and vulnerability scanning by leveraging Python's threading capabilities to execute multiple tasks in parallel.

The tool supports subdomain enumeration, DNS queries, HTTP status code checks, Shodan lookups, vulnerability scanning (XSS and SQLi), port scanning, and more. With customizable thread limits, Piga Hacks provides a streamlined and customizable recon experience.

## Features

- **Multi-threaded Execution**: Perform tasks concurrently with a customizable number of threads.
- **Subdomain Enumeration**: Quickly scan for subdomains of a domain.
- **DNS Scanning**: Query DNS records for a list of domains.
- **HTTP Status Code Checks**: Retrieve HTTP response codes from target domains.
- **Vulnerability Scanning**:
  - XSS vulnerability scanning.
  - SQL Injection vulnerability scanning.
- **Shodan Integration**: Perform Shodan lookups using an API key.
- **Web Crawling**: Crawl target websites for URLs, JavaScript files, and more.
- **Wayback URLs**: Fetch historical URLs from the Wayback Machine.
- **Port Scanning**: Integrate with Nmap for comprehensive port scans.
- **CIDR Notation Scanning**: Scan a range of IP addresses using CIDR notation.

## Installation

### Prerequisites

- **Python 3.6+**
- The following Python libraries:
  - `requests`
  - `beautifulsoup4`
  - `dnspython`
  - `shodan`

To install dependencies, run:

```bash
pip install -r requirements.txt
