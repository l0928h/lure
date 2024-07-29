import requests
import argparse
from bs4 import BeautifulSoup
from termcolor import cprint

class DedecmsScanner:
    def __init__(self, url, output_file=None):
        self.url = url
        self.output_file = output_file
        self.vulnerabilities = []

    def check_version(self):
        version = None
        try:
            response = requests.get(self.url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                meta_generator = soup.find('meta', {'name': 'generator'})
                if meta_generator and 'dedecms' in meta_generator.get('content', '').lower():
                    version = meta_generator['content']
        except Exception as e:
            cprint(f"[ERROR] Error checking version: {e}", 'red')
        return version

    def scan_sql_injection(self):
        payload = "' OR '1'='1"
        test_url = f"{self.url}/plus/search.php?keyword={payload}"
        try:
            response = requests.get(test_url)
            if "syntax error" in response.text.lower():
                self.vulnerabilities.append("SQL Injection")
        except Exception as e:
            cprint(f"[ERROR] Error scanning for SQL Injection: {e}", 'red')

    def scan_xss(self):
        payload = "<script>alert(1)</script>"
        test_url = f"{self.url}/plus/search.php?keyword={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                self.vulnerabilities.append("Cross-Site Scripting (XSS)")
        except Exception as e:
            cprint(f"[ERROR] Error scanning for XSS: {e}", 'red')

    def run_scan(self):
        cprint(f"[INFO] Scanning {self.url}...", 'cyan')
        version = self.check_version()
        if version:
            cprint(f"[INFO] Detected Dedecms version: {version}", 'green')
        else:
            cprint("[WARNING] Could not detect Dedecms version", 'yellow')

        self.scan_sql_injection()
        self.scan_xss()

        if self.vulnerabilities:
            cprint(f"[INFO] Vulnerabilities found: {', '.join(self.vulnerabilities)}", 'red')
            if self.output_file:
                with open(self.output_file, 'a') as f:
                    f.write(f"{self.url} - {', '.join(self.vulnerabilities)}\n")
        else:
            cprint("[INFO] No vulnerabilities found", 'green')

def scan_from_file(file_path, output_file=None):
    with open(file_path, 'r') as file:
        targets = file.readlines()
    
    for target in targets:
        target = target.strip()
        if target:
            scanner = DedecmsScanner(target, output_file)
            scanner.run_scan()

def main():
    parser = argparse.ArgumentParser(description='扫描Dedecms目标以识别漏洞')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='目标URL')
    group.add_argument('-f', '--file', help='包含目标URL的文件路径')
    parser.add_argument('-o', '--output', help='保存成功目标的文件路径')
    
    args = parser.parse_args()
    
    if args.url:
        scanner = DedecmsScanner(args.url, args.output)
        scanner.run_scan()
    elif args.file:
        scan_from_file(args.file, args.output)

if __name__ == "__main__":
    main()



