import requests
import argparse
from urllib.parse import urljoin
from termcolor import cprint

def get_geoserver_signature(url):
    try:
        cprint(f"[INFO] testing URL '{url}'", 'cyan')
        response = requests.get(url, timeout=10)
        headers = response.headers

        # 检查响应头中的服务器信息
        server_header = headers.get('Server', '')
        if 'GeoServer' in server_header:
            cprint(f"[INFO] found GeoServer signature in server header: {server_header}", 'green')
            return True

        # 检查特定端点的响应内容
        test_endpoints = [
            'geoserver/web/',
            'geoserver/rest/',
            'geoserver/wfs',
            'geoserver/wms'
        ]
        
        for endpoint in test_endpoints:
            full_url = urljoin(url, endpoint)
            cprint(f"[INFO] testing endpoint '{full_url}'", 'cyan')
            response = requests.get(full_url, timeout=10)
            if 'GeoServer' in response.text or 'geoserver' in response.text.lower():
                cprint(f"[INFO] found GeoServer signature at endpoint: {full_url}", 'green')
                return True

    except requests.RequestException as e:
        cprint(f"[ERROR] request to URL '{url}' failed: {e}", 'red')

    cprint(f"[WARNING] no GeoServer signature found for URL '{url}'", 'yellow')
    return False

def scan_targets(file_path, output_file=None):
    with open(file_path, 'r') as file:
        targets = file.readlines()
    
    if output_file:
        output_handle = open(output_file, 'a')
    
    for target in targets:
        target = target.strip()
        if target:
            cprint(f"[INFO] scanning target: {target}", 'cyan')
            if get_geoserver_signature(target):
                cprint(f"[INFO] {target} 可能是GeoServer服务", 'green')
                if output_file:
                    output_handle.write(target + '\n')
                    output_handle.flush()
            else:
                cprint(f"[WARNING] {target} 不是GeoServer服务或无法确定", 'yellow')
    
    if output_file:
        output_handle.close()
    
    cprint("[INFO] target scan completed.", 'cyan')

def main():
    parser = argparse.ArgumentParser(description='扫描多个目标以识别GeoServer服务')
    parser.add_argument('-f', '--file', required=True, help='包含目标URL的文件路径')
    parser.add_argument('-o', '--output', help='保存成功目标的文件路径')
    
    args = parser.parse_args()
    
    file_path = args.file
    output_file = args.output
    scan_targets(file_path, output_file)

if __name__ == "__main__":
    main()







