# WebHunter
![WebHunter](file_00000000f24c624390b83fee6b6160ae.png)
## Overview

`WebHunter` is a powerful and comprehensive tool for automating web reconnaissance and discovering security vulnerabilities. This tool is designed to be an all-in-one solution for security testers, developers, and system administrators, providing a wide range of modules that cover multiple aspects of web security, from basic information gathering to advanced vulnerability scanning.

## Main Features

* **Full Scan**: The ability to perform a full scan that includes all available modules, providing a comprehensive view of the target.
* **Information Gathering**: Collect basic information about the target, including IP address, HTTP status, page title, server information, and detected technologies.
* **DNS Analysis**: Inspect various DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) to gain a deeper understanding of the target’s infrastructure.
* **WHOIS Lookup**: Perform a WHOIS lookup to obtain domain registration information.
* **SSL/TLS Checking**: Verify the site’s SSL/TLS certificate to obtain details about encryption and certificate validity.
* **Technology Detection**: Identify technologies used by the site, such as content management systems (WordPress, Joomla, Drupal), frameworks (jQuery, Bootstrap, React), and programming languages (PHP, ASP.NET).
* **Subdomain Enumeration**: Discover target subdomains using a wordlist.
* **Port Scanning**: Scan common ports to identify services running on the server.
* **Web Crawling**: Crawl the site to collect links, forms, email addresses, and comments.
* **Vulnerability Scanning**: Scan for common security vulnerabilities, including:
  * **Cross-Site Scripting (XSS)**
  * **SQL Injection (SQLi)**
  * **Local File Inclusion (LFI)**
  * **Directory Traversal**
* **SEO & Performance Analysis**: Basic analysis for search engine optimization (SEO) and site performance, including load time and page size.
* **Sensitive Files Detection**: Search for potentially exposed sensitive files, such as configuration files, backups, and access logs.
* **Result Storage**: Save scan results into an SQLite database and a JSON file for easy review and analysis.

## Installation

To get started with `WebHunter`, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/AL-MARID/webhunter.git
    cd webhunter
    ```

2. **Install dependencies**:  
    The tool requires a set of Python libraries. You can install them using `pip`:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run `WebHunter`, execute the script `webhunter.py` from the command line:

```bash
python webhunter.py
 ```

