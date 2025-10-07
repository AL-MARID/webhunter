# WebHunter
![WebHunter](file_00000000f24c624390b83fee6b6160ae.png)
## Overview

`WebHunter` is a powerful and comprehensive tool for automating web reconnaissance and vulnerability discovery processes. This tool is designed to be an all-in-one solution for security testers, developers, and system administrators, providing a wide range of modules covering multiple aspects of web security, from basic information gathering to advanced vulnerability scanning.

## Key Features

*   **Comprehensive Scanning**: Ability to perform a full scan including all available modules, providing a comprehensive view of the target.
*   **Information Gathering**: Gather basic information about the target, including IP address, HTTP status, page title, server information, and technologies used.
*   **DNS Analysis**: Examine various DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) for a deeper understanding of the target's infrastructure.
*   **WHOIS Lookup**: Perform a WHOIS lookup to get information about domain registration.
*   **SSL/TLS Scan**: Verify the site's SSL/TLS certificate for details about encryption and certificate validity.
*   **Technology Discovery**: Identify technologies used on the site, such as Content Management Systems (WordPress, Joomla, Drupal), frameworks (jQuery, Bootstrap, React), and programming languages (PHP, ASP.NET).
*   **Subdomain Enumeration**: Discover target subdomains using a common wordlist.
*   **Port Scanning**: Scan common ports to identify open services on the server.
*   **Web Crawling**: Crawl the site to gather links, forms, email addresses, and comments.
*   **Vulnerability Scanning**: Scan for common security vulnerabilities, including:
    *   **Cross-Site Scripting (XSS)**
    *   **SQL Injection (SQLi)**
    *   **Local File Inclusion (LFI)**
    *   **Directory Traversal**
*   **SEO & Performance Analysis**: Basic analysis for Search Engine Optimization (SEO) and site performance, including load time and page size.
*   **Sensitive Files Detection**: Search for sensitive files that might be exposed, such as configuration files, backups, and access logs.
*   **Save Results**: Save scan results in an SQLite database and a JSON file for easy review and analysis.

## Installation

To start using `WebHunter`, follow these steps:

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/AL-MARID/webhunter.git
    cd webhunter
    ```

2.  **Install dependencies**:
    The tool requires a set of Python libraries. You can install them using `pip`:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run `WebHunter`, execute the `webhunter.py` script from the command line:

```bash
python webhunter.py
```

You will be prompted to enter the target URL, then choose the type of scan you wish to perform from the following menu:

1. Full Scan (All modules)
2. Information Gathering (Info, DNS, WHOIS, SSL, Tech)
3. Subdomain Enumeration
4. Port Scanning
5. Web Crawling
6. Vulnerability Scanning (XSS, SQLi, LFI, Directory Traversal)
7. SEO & Performance Analysis
8. Sensitive Files Detection
9. DNS Analysis (including reverse DNS and zone transfer)
10. Advanced Subdomain Enumeration (Multiple Methods)

After the scan is complete, the results will be saved in a JSON file named scan_<target_domain>_<timestamp>.json and in the webhunter_scans.db database.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Contributing

Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, please feel free to:

1. Fork the repository.
2. Create a new branch (git checkout -b feature/YourFeature).
3. Make your changes and commit them (git commit -m 'Add some feature').
4. Push to the branch (git push origin feature/YourFeature).
5. Open a Pull Request.
