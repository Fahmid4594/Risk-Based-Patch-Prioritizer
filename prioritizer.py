import json
import requests
import argparse
import logging
import sys



parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True, help="Path to the vulnerability scan JSON file.")
args = parser.parse_args()

with open(args.input,'r') as file: 
    scan_data = json.load(file) 
    

cve_list = []

if "Results" not in scan_data:
    logging.info("No vulnerabilities found in the scanned data. System is secure.")
    sys.exit(0)

for result in scan_data["Results"]:
    if "Vulnerabilities" in result:
        for vulnerability in result["Vulnerabilities"]:
            cve_list.append(vulnerability["VulnerabilityID"])



unique_cves = list(set(cve_list)) 
cisa_web_request = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json") 
cisa_data = cisa_web_request.json() 
cisa_vulnerability_list = cisa_data["vulnerabilities"]
cisa_matched_cves = []

for cve in unique_cves : 
    for cisa_vulnerability in cisa_vulnerability_list: 
        if cve == cisa_vulnerability["cveID"]:
            cisa_matched_cves.append(cve)
            print(f"Match Found: {cve}") 

final_risk_list = []

for cve in cisa_matched_cves:
    try: 
        epss_request = requests.get(f"https://api.first.org/data/v1/epss?cve={cve}") 
        epss_score = epss_request.json()
        extracted_score = epss_score["data"][0]["epss"] 
        print(f"{cve} has a threat score of {extracted_score}")
        vulnerability_data = {"vulnerability" : cve, "threat_score": extracted_score}
        final_risk_list.append(vulnerability_data)  
    except requests.exceptions.RequestException: 
        print(f"Warning: API failed for {cve}")






final_risk_list.sort(key=lambda x: float(x["threat_score"]), reverse = True )
print(final_risk_list) 
for counter, risk in enumerate(final_risk_list, start = 1):
    cve_name = risk["vulnerability"] 
    score = risk["threat_score"]
    print(f"{counter:<3} {cve_name:<25} | {score:<20}")



    








