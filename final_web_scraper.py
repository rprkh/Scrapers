import sys
import requests
from bs4 import BeautifulSoup
import csv
import os
import threading
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import re

@dataclass
class CONFIG:
    CVES_DIRECTORY = "CVEs" 

def setup_session(url: str):
    try:
        session = requests.Session()
        session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.1.2222.33 Safari/537.36",
            "Accept-Encoding": "*",
            "Connection": "keep-alive"
        }
        response = session.get(url)
        return response
    except:
        pass

def scrape_page(url, existing_cves):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all the table rows (excluding the header)
    rows = soup.find_all('tr', {'data-testid': re.compile(r'vuln-row-\d+')})
   # print(f"Found {len(rows)} rows on the page: {url}")

    data = []
    for row in rows:
        cve_id = row.find('a', {'data-testid': re.compile(r'vuln-detail-link-\d+')}).text.strip()
        summary = row.find('p', {'data-testid': re.compile(r'vuln-summary-\d+')}).text.strip()
        published_date = row.find('span', {'data-testid': re.compile(r'vuln-published-on-\d+')}).text.strip()
        cvss_link = row.find('a', {'data-testid': re.compile(r'vuln-cvss3-link-\d+')})
        cvss_v3_1 = cvss_link.text.strip() if cvss_link else ''

        # Check if CVE already exists in the CSV file
        if cve_id not in existing_cves:
            data.append([cve_id, summary, published_date, cvss_v3_1])

    return data

# Function to scrape all pages for a company
def scrape_company_pages(keyword, page, existing_cves):
    base_url = f"https://nvd.nist.gov/vuln/search/results?query={keyword}&results_type=overview&form_type=Basic&search_type=all"
    url = f"{base_url}&startIndex={page * 20}"
    print(f"Scraping page {page+1} for {keyword}")
    return scrape_page(url, existing_cves)

# Function to scrape all pages for a company using threading
def scrape_all_company_pages(keyword):
    base_url = f"https://nvd.nist.gov/vuln/search/results?query={keyword}&results_type=overview&form_type=Basic&search_type=all"
    response = requests.get(base_url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Extracting total number of records
    total_records = int(soup.find('strong', {'data-testid': 'vuln-matching-records-count'}).text.strip().replace(',', ''))

    # Calculating total pages
    total_pages = (total_records // 20) + 1

    # Check if CSV file exists for the company
    csv_filename = f'CVEs/cve_data_{keyword}.csv'
    existing_cves = set()
    if os.path.exists(csv_filename):
        with open(csv_filename, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                existing_cves.add(row[0])  # Add CVE ID to set
        
    company_data = []
    with ThreadPoolExecutor() as executor:
        results = [executor.submit(scrape_company_pages, keyword, page, existing_cves) for page in range(total_pages)]
        for future in results:
            company_data.extend(future.result())

    if company_data:
        # Writing data to CSV file
        header = ["CVE", "Summary", "NVD Published Date", "CVSS"]
        with open(csv_filename, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            # Add header if file is empty
            if os.stat(csv_filename).st_size == 0:
                writer.writerow(header)
            for row in company_data:
                writer.writerow(row)
        print(f"CSV file updated for {keyword}.")
    else:
        print(f"No new data found for {keyword}.")

    executor.shutdown()