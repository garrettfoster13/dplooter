import requests
from bs4 import BeautifulSoup
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
import argparse
import re
import hashlib
import os
from rich.console import Console

console = Console()

def isdir(url):
    '''
    Check if the link is a directory for recursive searching
    '''
    if url.endswith('/'):
        return True
    if not re.search(r'\.[a-zA-Z0-9]+$', url):
        return True
    return False

def build_pkg_inventory(target, username, password, status):
    '''
    Parse all of the .INI files for endpoints
    '''
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    url = f"https://{target}/sms_dp_smspkg$/pkglib"
    pkg_urls = []

    try:
        r = requests.get(f"{url}",
                            auth=HttpNtlmAuth(username, password),
                            verify=False)
        if r.status_code == 200:
            print("[+] Querying packages.")
            soup = BeautifulSoup(r.text, 'html.parser')
            anchor_tags = soup.find_all('a', href=True)
            for i in anchor_tags:
                url = (i['href'])
                if url.endswith('.INI'):
                    endpoint = url.split("/")[-1].replace(".INI", "")
                    newurl = f"https://{target}/sms_dp_smspkg$/{endpoint}"
                    pkg_urls.append(newurl)
        if r.status_code == 404:
            print(f"Got status code 404 for {url}.")
        if r.status_code == 401:
            print("Got status code 401. Check your credentials and try again.")
    except Exception as e:
        print(e)
    return pkg_urls


def build_file_inventory(username, password, pkg_urls, status):
    '''
    Read the package urls and list out everything. Download filters apply
    after the inventory to prevent multiple collection runs.
    '''
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    pkg_files = []
    for url in pkg_urls:
        try:
            r = requests.get(f"{url}",
                                auth=HttpNtlmAuth(username, password),
                                verify=False)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                anchor_tags = soup.find_all('a', href=True)
                for i in anchor_tags:
                    url = (i['href'])
                    if isdir(url):
                        nested = build_file_inventory(username, password, [url], status)
                        if nested is not None:
                            pkg_files.extend(nested)
                    else:
                        pkg_files.append(url)
            if r.status_code == 404:
                print(f"Got status code 404 for {url}.")
            if r.status_code == 401:
                print("Got status code 401. Check your credentials and try again.")
        except Exception as e:
            print(e)
    return pkg_files

def save_inventory(urls):
    length = len(urls)
    with open("package_inventory.txt", 'w') as f:
        for url in urls:
            f.write("{}\n".format(url))
    print(f"Saved {length} discovered packages to {os.getcwd()}/package_inventory.txt.")
    f.close()
    return

def save_file_list(files):
    length = len(files)
    with open("file_inventory.txt", 'w') as f:
        for file in files:
            f.write("{}\n".format(file))
    f.close()
    print(f"Saved {length} discovered files to {os.getcwd()}/file_inventory.txt.")
    return
    
def read_files(extensions):
    try: 
        with open('file_inventory.txt', 'r') as file:
            urls = file.readlines()
            if extensions:
                extensions = [f".{ext}" for ext in extensions]
                urls = [url for url in urls if any(url.strip().endswith(ext) for ext in extensions)]
                return urls
            else:
                return urls
    except FileNotFoundError:
        print('Inventory list not found. Run inventory check first.')
        return

def download_files(username, password, status, extensions):
    count = 0
    if not os.path.isdir("downloads"):
        os.mkdir("downloads")
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    #load and parse the inventory file
    urls = read_files(extensions)
    if urls:
        for url in urls:
            count += 1
            status.update(f"Downloaded {count} files.")
            url = url.strip()
            if url:
                try:    
                    r = requests.get(f"{url}",
                                    auth=HttpNtlmAuth(username, password),
                                    verify=False)
                    if r.status_code == 200:
                        # hash the file incase we get duplicate entries
                        hash = hashlib.md5(r.content).hexdigest()
                        file = url.split("/")[-1]
                        file_name = hash + "_" + file
                        with open(f"downloads/{file_name}", 'wb') as file:
                            file.write(r.content)
                except Exception as e:
                    print(e)
        print(f"Done. Saved {count} files to disk.")



def arg_parse():
    parser = argparse.ArgumentParser(add_help=True, description="Fuzz Distribution Point packages via HTTP(s)")

    parser.add_argument("-t", "--target", action="store", help="Target DP IP or hostname.")
    parser.add_argument("-u", "--user", action="store", help="Site Server Admin Username.")
    parser.add_argument("-p", "--password", action="store", help="Site Server Admin Password or Hash (LMHASH:NTHASH")
    parser.add_argument("-d", "--download", action="store_true", help="Download files found from fuzzing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-e", "--extension", action="store", help="filter for file extension. Comma separated list ex: 'ps1,exe,dll' ", required=False)

    args = parser.parse_args()
    return args


def run():
    args = arg_parse()
    username = args.user
    password = args.password
    target = args.target
    extensions = args.extension
    download = args.download

    with console.status(f"", spinner="dots") as status:
        #check if we're just downloading
        if download:
            # only download files with user provided extensions
            if extensions:
                extensions = extensions.split(",")
            download_files(username, password, status, extensions)
        else:
            pkgurls = build_pkg_inventory(target, username, password, status)
            if pkgurls:
                save_inventory(pkgurls)
                pkg_files = build_file_inventory(username, password, pkgurls, status)
                if pkg_files:
                    save_file_list(pkg_files)
            else:
                print("no endpoints found")


    return

run()

