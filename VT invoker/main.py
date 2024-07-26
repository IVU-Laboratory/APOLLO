import pandas as pd
import os
import requests
import base64
import time
import json
from dotenv import load_dotenv


GENUINE_EMAILS = False
START_INDEX = 1500
END_INDEX = 1999
PHISH_TANK = True


def get_virustotal_data(url):
    api_base_url = 'https://www.virustotal.com/api/v3/urls/'
    vt_api_key = os.getenv("VT_API")  # VirusTotal API key - https://www.virustotal.com/gui/home/upload
    # Headers with the API key
    headers = {
        'x-apikey': vt_api_key,
    }
    try:
        base_64_url = base64.b64encode(url.encode('ascii')) # encode the url in base64 bytes
        base_64_url = base_64_url.decode("ascii")  # get the base64 string
        base_64_url = base_64_url.rstrip('=')  # remove the trailing padding chars '='
        request_url = api_base_url + base_64_url
        response = requests.get(request_url, headers=headers) # Make the HTTP GET request
        # Check for a successful response (HTTP status code 200)
        if response.status_code == 200:
            # Access the JSON response
            result = response.json()
            vt_data = result['data']['attributes']['last_analysis_stats']  # contains the votes for the scan {"harmless" : w, "undetected": x, "suspicious": y, "malicious": z}
        else:
            print(f"VirusTotal Request failed with status code: {response.status_code}")
            vt_data = "Unknown"
        response.close()  # Close the response
        return vt_data
    except:
        return "Unknown"


# Blackist Checker API
def get_blacklists_data(url):
    blacklist_api_key = os.getenv("BLACKLIST_API")  # Blacklist Checker API key - https://blacklistchecker.com/
    api_base_url = "https://api.blacklistchecker.com/"
    request_url = api_base_url + "check/" + url
    try:
        response = requests.get(request_url, auth=(blacklist_api_key, ""))  # Make the HTTP GET request

        # Check for a successful response (HTTP status code 200)
        if response.status_code == 200:
            # Access the JSON response
            result = response.json()
        else:
            print(f"BlacklistChecker Request failed with status code: {response.status_code}")
            result = {"detections": "Unknown"}
        n_blacklists_found = result["detections"]  # The detections field simply carries the number of blacklists in which the domain appeared

        response.close() # Close the response
        return n_blacklists_found
    except:
        return "Unknown"


def load_emails(csv_files):
    emails_df = pd.DataFrame()
    print("Loading emails...")
    for file_name in csv_files:
        df = pd.read_csv(os.path.join('datasets', file_name), sep=",")
        emails_df = pd.concat([emails_df, df])

    return emails_df


def main_vt():
    DAILY_LIMIT = 500
    RATE_LIMIT = 4  # Maximum API calls per minute
    DELAY = 60 / RATE_LIMIT  # Delay between calls
    if PHISH_TANK:
        phish_tank_df = pd.read_csv(os.path.join('datasets',"phish_tank.csv"))
        # Get only urls in the specified range
        phish_tank_df = phish_tank_df.iloc[START_INDEX:END_INDEX]
        urls = phish_tank_df["url"]
    else:
        emails_df = load_emails(["legit.csv", "phishing.csv"])
        # get genuine or phishing emails only
        label = 0 if GENUINE_EMAILS else 1
        emails_df = emails_df[emails_df["label"] == label]
        # Get only emails in the specified range
        emails_df = emails_df.iloc[START_INDEX:END_INDEX]
        # Extract the URLS of the emails
        urls = emails_df["urls"]

    results = {}
    computed = 0
    for i, email_urls in enumerate(urls):
        email_urls = email_urls.split()  # there are 1 or more urls in each email
        for url in email_urls:
            if url not in results:  # if it wasn't processed already
                print(f"Processing {url} - {START_INDEX + i}")
                vt_data = get_virustotal_data(url)
                if vt_data != "Unknown":
                    computed += 1
                    results[url] = vt_data
                    if computed >= DAILY_LIMIT:
                        break
                    print(f'Waiting for {DELAY} seconds...')
                    time.sleep(DELAY)
        if computed >= DAILY_LIMIT:
            break
    """Saves results to a JSON file."""
    label = 'legit' if GENUINE_EMAILS else 'phishing'
    label = 'phishtank' if PHISH_TANK else label
    output_file = f"vt_results_{START_INDEX}-{END_INDEX}_{label}.json"
    with open(output_file, 'w') as file:
        json.dump(results, file, indent=4)


def main_blacklist():
    if PHISH_TANK:
        phish_tank_df = pd.read_csv(os.path.join('datasets',"phish_tank.csv"))
        # Get only urls in the specified range
        phish_tank_df = phish_tank_df.iloc[START_INDEX:END_INDEX]
        urls = phish_tank_df["url"]
    else:
        emails_df = load_emails(["legit.csv", "phishing.csv"])
        # get genuine or phishing emails only
        label = 0 if GENUINE_EMAILS else 1
        emails_df = emails_df[emails_df["label"] == label]
        # Get only emails in the specified range
        emails_df = emails_df.iloc[START_INDEX:END_INDEX]
        # Extract the URLS of the emails
        urls = emails_df["urls"]

    results = {}
    computed = 0
    for i, email_urls in enumerate(urls):
        email_urls = email_urls.split()  # there are 1 or more urls in each email
        for url in email_urls:
            if url not in results:  # if it wasn't processed already
                print(f"Processing {url} - {i}")
                result_data = get_blacklists_data(url)
                if result_data != "Unknown":
                    computed += 1
                    results[url] = result_data
    """Saves results to a JSON file."""
    output_file = f"blacklists_results_{START_INDEX}-{END_INDEX}_{'legit' if GENUINE_EMAILS else 'phishing'}.json"
    with open(output_file, 'w') as file:
        json.dump(results, file, indent=4)


if __name__ == "__main__":
    load_dotenv()
    class_to_evaluate = 'Legit' if GENUINE_EMAILS else 'Phishing'
    choice = input(f"Choose service to evaluate:\n(1) VirusTotal\n(2) Blacklist Checker"
                   f"\nIndexes: {START_INDEX}-{END_INDEX}   ----   {'PhishTank' if PHISH_TANK else class_to_evaluate}"
                   f"\nChoice: ")
    if choice == "1":
        main_vt()
    elif choice == "2":
        main_blacklist()
    else:
        print("Invalid choice")
