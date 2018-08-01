# coding: utf-8
import os,json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

path = b'./report/virusshare'
total = {}

# ========== VirusTotalのjsonはおかしいので修正 ==========
def fix_json(file):
    file = file.replace('\'','"')
    file = file.replace('True','true')
    file = file.replace('False','false')
    file = file.replace('None','null')
    return file

def fix_file(file):
    with open(file, 'r') as f:
        filedata = f.read()
    filedata = fix_json(filedata)
    with open(file, 'w') as f:
        f.write(filedata)

# ========== 検知回数を数える ==========
def scan_count(scans):
    for k, v in scans.items():
        if (v["detected"]):
            if k not in total.keys():
                total[k] = 1 
            else:
                total[k] += 1

# ========== グラフを描画 ==========
def graph(a,b,c,d):
    plt.rcParams['font.family'] = 'Yu Gothic'
    labels = ['パック前データ1', 'パック後データ1', 'パック前データ2', 'パック後データ2']
    height = [a, b, c, d]
    fig, ax = plt.subplots(1,1)
    ax.bar(labels, height, width=0.6)
    plt.ylim([-100,0])
    plt.ylabel('誤検知率(%)')
    plt.title('正常ファイルの誤検知率')
    plt.tight_layout()
    plt.show()
    plt.savefig('benign.png')

# ========== ディレクトリの中全てのファイルについて ==========
for dir in os.listdir(os.fsencode(path)):
    for f in os.listdir(os.path.join(path,dir)):
        fix_file(os.path.join(path,dir,f))
        with open(os.path.join(path,dir,f), 'r') as f:
            json_obj = json.load(f)
            if "scans" in json_obj.keys():
                scan_count(json_obj["scans"])
            else:
                continue
print(total)
