import requests
import time

API_KEY = "YOUR_KEY"
INPUT_FILE = "domains.txt"
OUTPUT_FILE = "results.csv"

def check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    return response

with open(INPUT_FILE) as f, open(OUTPUT_FILE, "w") as out:
    out.write("Domain,Harmless,Malicious,Suspicious,Undetected\n")
    
    domains = [d.strip() for d in f.readlines()]
    
    for i, domain in enumerate(domains):
        print(f"[{i+1}/{len(domains)}] Checking: {domain}")
        
        response = check_domain(domain)
        
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            out.write(f"{domain},{stats['harmless']},{stats['malicious']},{stats['suspicious']},{stats['undetected']}\n")
        else:
            out.write(f"{domain},ERROR,ERROR,ERROR,ERROR\n")
        
        # 4 requests per minute ⇒ delay 15 seconds after each request
        time.sleep(15)

print("Done!")
