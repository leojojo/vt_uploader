#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import sys,os,requests,json,textwrap
from dotenv import load_dotenv
from time import sleep
from progressbar import ProgressBar

class VirusTotalUploader:
    def __init__(self):
        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)
        self.API_KEY= os.environ.get('API_KEY')
        self.request_ctr = 0
        self.scan_id_list = []
        self.base_url = 'https://www.virustotal.com/vtapi/v2/file/'
        
    # ========== ファイルを投げる ==========
    def submit_file(self, path):
        progress = ProgressBar(0, len(os.listdir(path)))
        params = { 'apikey': self.API_KEY }
        files = os.listdir(os.fsencode(path))

        for index,f in enumerate(files):
            if f.startswith(b'.'):
                continue

            if self.request_ctr >= 4:
                sleep(60)
                self.request_ctr = 0

            filename = f.decode('utf-8')
            files = { 'file': (filename,
                open(os.path.join(path,f.decode('utf-8')), 'rb')) }
            response = requests.post(self.base_url + 'scan',
                    files=files, params=params)
            self.request_ctr += 1
            scan_id = str(response.json()['scan_id'])
            self.scan_id_list.append(scan_id)

            progress.update(index)

    # ========== レポートを受け取る ==========
    def request_report(self,path):
        os.makedirs('report', exist_ok=True)

        for index,scan_id in enumerate(self.scan_id_list):
            if self.request_ctr >= 4:         # 4リクエスト / 分
                sleep(60)
                self.request_ctr = 0

            params = {
                'apikey': self.API_KEY,
                'resource': scan_id
              }
            headers = {
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent' : 'python requests library'
              }
            response = requests.get(self.base_url + 'report',
                    params=params, headers=headers)
            self.request_ctr += 1
            result = str(response.json())

            with open(os.path.join('report', str(index)+'.json'), 'a') as f:
                f.write(result)

def main():
    for arg in sys.argv[1:]:
        v = VirusTotalUploader()
        v.submit_file(arg)
        v.request_report(arg)

if __name__ == '__main__':
    main()
