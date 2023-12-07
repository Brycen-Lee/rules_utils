import json
desc_path='C:\\Users\yonggui_li\\Downloads\\NSPattern_nsc_2000.012.tar\\NSPattern_nsc_2000.012\\description.json'
cve_path="D:\\work\\ruleUtils-rs\\ns_rules_utils\\src\\cve.txt"

cves = []
with open(cve_path, 'r') as file:
    for line in file:
        if line != None:
            cve = line.replace("\n","")
            cves.append(cve)

print(cves)


rule_cve = {}
with open(desc_path, "r", encoding="utf-8") as json_file:
    desc_json = json.load(json_file)
    for key, value in desc_json.items():
        # print(key, value)
        rule_cve[key] = value["cves"]

for cve in cves:
    flag = False
    for rule, cve_m in rule_cve.items():
        if cve in cve_m:
            print(cve, rule)
            flag = True
            break
    
    if not flag:
        print(cve)