# coding: utf-8
import sys,os,json

# ========== VirusTotalのjsonはおかしいので修正 ==========
def fix_file(file):
    def fix_json(file):
        file = file.replace('\'','"')
        file = file.replace('True','true')
        file = file.replace('False','false')
        file = file.replace('None','null')
        return file

    with open(file, 'r') as f:
        filedata = f.read()
    filedata = fix_json(filedata)
    with open(file, 'w') as f:
        f.write(filedata)

# ========== 検知回数を数える ==========
def analyze(file):
    detect_ctr = 0
    not_detect_ctr = 0

    def scan_count(scans):
        nonlocal detect_ctr
        nonlocal not_detect_ctr
 
        for k, v in scans.items():
            if (v["detected"]):
                detect_ctr += 1
            elif (not(v["detected"])):
                not_detect_ctr += 1
            else:
                print('err')

    fix_file(file)
    with open(file, 'r') as f:
        json_obj = json.load(f)
        if "scans" in json_obj.keys():
            scan_count(json_obj["scans"])
    print('detected: {0}\nnot detected: {1}'.format(detect_ctr, not_detect_ctr))

def main():
    for arg in sys.argv[1:]:
        analyze(arg)

if __name__ == "__main__":
    main()
