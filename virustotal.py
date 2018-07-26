# coding: utf-8
import os
import requests
import json
import textwrap
import config
from time import sleep

request_ctr = 0

# ========== ファイルを投げる ==========
scan_id_list = []
params = { 'apikey': config.API_KEY }
directory = os.fsencode(config.path)
for f in os.listdir(directory):

    if request_ctr > 4:         # 4リクエスト / 分
        sleep(60)
        request_ctr = 0

    filename = f.decode('utf-8')
    files = { 'file': (filename, open(os.path.join(config.path,f), 'rb')) }
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan',
            files=files, params=params)
    request_ctr += 1
    scan_id = str(response.json()['scan_id'])
    scan_id_list.append(scan_id)
    print(filename + ': ' + scan_id)

# ========== レポートを受け取る ==========
os.makedirs('report', exist_ok=True)

for index,scan_id in enumerate(scan_id_list):
    print(str(request_ctr) + ': ' + str(scan_id))

    if request_ctr > 4:         # 4リクエスト / 分
        sleep(60)
        request_ctr = 0

    params = {
        'apikey': config.API_KEY,
        'resource': scan_id
      }
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent' : 'python requests library'
      }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
            params=params, headers=headers)
    request_ctr += 1
    result = str(response.json())
    print(textwrap.shorten(result, width=100, placeholder="..."))

    with open(os.path.join('report', str(index)+'.json'), 'a') as f:
        f.write(result)
