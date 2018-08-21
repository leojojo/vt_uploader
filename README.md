# Virustotal Uploader
## Usage
- First, create `.env` and write your [API key](https://www.virustotal.com/#/join-us) using `.env.sample` as reference.  

- `pip install -r requirements.txt`

- `python virustotal.py [directory]`  
saves reports from VirusTotal in json ([response format](https://www.virustotal.com/ja/documentation/public-api/#getting-file-scans)) in `reports` directory.  

- `python analysis.py [file]`  
from the reports, sums the number of times each vendor detected malware  

- `python batch_analysis.py [directory]`  
from the reports, sums the number of times each vendor detected malware  

---
## 使い方
- まず、`.env.sample`を参考に`.env`を作成して[API key](https://www.virustotal.com/#/join-us)を記述してください。  

- `pip install -r requirements.txt`

- ` python virustotal.py [directory]`  
`reports`ディレクトリにVirusTotalからのレポートをjson([レスポンス形式](https://www.virustotal.com/ja/documentation/public-api/#getting-file-scans))で保存します。  

- `python analysis.py [file]`  
VirusTotalからのjson形式のレスポンスを集計して、どのベンダーが何回検知したかを集計します。  

- `python batch_analysis.py [directory]`  
VirusTotalからのjson形式のレスポンスを集計して、どのベンダーが何回検知したかを集計します。  
