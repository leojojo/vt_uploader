# coding: utf-8
import sys,os,json

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

# ========== ディレクトリの中全てのファイルについて ==========
def analyze(file):
    fix_file(file)
    with open(file, 'r') as f:
        json_obj = json.load(f)
        if "scans" in json_obj.keys():
            scan_count(json_obj["scans"])
    print(total)

def main():
    for arg in sys.argv[1:]:
        print arg
        analyze(arg)

if __name__ == "__main__":
    main()
