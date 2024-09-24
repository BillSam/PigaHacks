# Test if required packages are installed properly

import requests
from bs4 import BeautifulSoup
import dns.resolver
import shodan

def test_requests():
    try:
        response = requests.get('https://www.google.com')
        if response.status_code == 200:
            print("requests: OK")
        else:
            print("requests: Failed")
    except Exception as e:
        print(f"requests: {e}")

def test_bs4():
    try:
        html = '<html><head><title>Test</title></head><body></body></html>'
        soup = BeautifulSoup(html, 'html.parser')
        if soup.title.string == "Test":
            print("beautifulsoup4: OK")
        else:
            print("beautifulsoup4: Failed")
    except Exception as e:
        print(f"beautifulsoup4: {e}")

def test_dnspython():
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve('google.com', 'A')
        print(f"dnspython: OK, IPs: {[rdata.to_text() for rdata in answer]}")
    except Exception as e:
        print(f"dnspython: {e}")

def test_shodan():
    try:
        api = shodan.Shodan('YOUR_SHODAN_API_KEY')  # Replace with a real API key for a valid test
        print("shodan: OK (API Key test not performed)")
    except Exception as e:
        print(f"shodan: {e}")

if __name__ == "__main__":
    test_requests()
    test_bs4()
    test_dnspython()
    test_shodan()
