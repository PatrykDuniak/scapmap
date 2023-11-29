import requests
from bs4 import BeautifulSoup
import os
import zipfile
import hashlib
import time
import re
from urllib.parse import urljoin
from .IPinterpreter import IPinterpreter

class WebScrapper(IPinterpreter):
    def __init__(self, targets, verify):
        super().__init__(targets)
        self.verify = verify
        self._links_by_depth = []

    def nameregex(self, url):
        pattern = r"[`!.?= \[\]/\\]"
        cleaned_text = re.sub(pattern, '', url)
        return cleaned_text

    def download_page_with_attachments(self):
        requests.packages.urllib3.disable_warnings() 
        url = self._targets
        # Function to download file
        def download_file(url, folder):
            requests.packages.urllib3.disable_warnings() 
            cleaned_url = self.nameregex(url.split('/')[-1])
            if len(cleaned_url) == 0:
                cleaned_url = 'null'
            local_filename = os.path.join(folder, cleaned_url)
            with requests.get(url, stream=True, verify=self.verify) as r:
                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            return local_filename

        # Download website
        response = requests.get(url, verify=self.verify)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Create folder to save data
        hash_object = hashlib.sha1(url.encode())
        folder_name = hash_object.hexdigest()[:10]  # 10 char as filename
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # Save website as html
        html_filename = os.path.join(folder_name, 'page.html')
        with open(html_filename, 'w', encoding='utf-8') as html_file:
            html_file.write(response.text)

        # Download images
        img_tags = soup.find_all('img')
        for img_tag in img_tags:
            img_url = img_tag.get('src')
            if img_url:
                img_url = urljoin(url, img_url)
                print(f"Download image: {img_url}")
                download_file(img_url, folder_name)

        # Download other things
        other_tags = soup.find_all(['audio', 'video', 'source', 'link'])
        for tag in other_tags:
            tag_url = tag.get('href') or tag.get('src')
            if tag_url and not tag_url.endswith('.js'):  # SKIP JS
                tag_url = urljoin(url, tag_url)
                print(f"Download misc: {tag_url}")
                download_file(tag_url, folder_name)

        print("Pobieranie zakończone!")

        # Create zip
        timestamp = str(int(time.time()))  # Timestamp
        zip_filename = hash_object.hexdigest()[:10] + '_' + timestamp + '.zip'
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_name):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path)

        # Hash from zip
        with open(html_filename, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        print(f"Archive '{zip_filename}' was created.")
        print(f"Checksum SHA256: '{file_hash}'")
        print(f"Remeber to encrypt file with strong algorithm and key!")

    def collect_links(self, depth, diffdomain=True):
        url = self._targets
        try:
            requests.packages.urllib3.disable_warnings() 
            response = requests.get(url, verify=self.verify)
            soup = BeautifulSoup(response.content, 'html.parser')
            links_at_depth = []
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                absolute_url = urljoin(url, href)
                if absolute_url in links_at_depth or 'javascript' in absolute_url:
                    continue
                if diffdomain == True:
                    if absolute_url.startswith(url):
                        links_at_depth.append(absolute_url)
                else:
                    links_at_depth.append(absolute_url)
            self._links_by_depth.append(links_at_depth) #add links to depth 0
            if depth > 0:
                for x in range(depth):
                    links_at_depth = []
                    counter = 0
                    for link in self._links_by_depth[x]:
                        counter += 1
                        print("Depth: "+str(x+1)+"        Iteration: "+str(counter)+"/"+str(len(self._links_by_depth[x])), end='\r')
                        response = requests.get(link, verify=self.verify)
                        soup = BeautifulSoup(response.content, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            href = link.get('href')
                            absolute_url = urljoin(url, href)
                            if absolute_url in links_at_depth or 'javascript' in absolute_url:
                                continue
                            if diffdomain == True:
                                if absolute_url.startswith(url):
                                    links_at_depth.append(absolute_url)
                            else:
                                links_at_depth.append(absolute_url)
                    self._links_by_depth.append(links_at_depth)  # Add links to specific depth

        
            for depth,links in enumerate(self._links_by_depth): #print function
                print(f"Level {depth}:")
                for link in links:
                    print(link)

        except Exception as e:
            print(f"An error occurred: {e}")