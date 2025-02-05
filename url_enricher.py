import requests
import base64
import dns.resolver
import socket
import re
import os


def get_fullhostname(url):
    # get the domain name from the URL (protocol + hostname, without the path)
    re_match = re.search(r"^(\w+:\/\/)?(?:[^@\/\n]+@)?((?:www\.)?[^:\/?\n]+)\:?(\d*)(\/[^?]*)?(\?.*)?", url, re.I)
    if re_match is not None:
        re_match = re_match.groups()
        protocol = re_match[0] or ""
        domain = re_match[1] or ""
        full_hostname = protocol + domain
        return full_hostname
    return url


def get_hostname(url):
    # get the domain name from the URL (without the path and the protocol)
    re_match = re.search(r"^(\w+:\/\/)?(?:[^@\/\n]+@)?((?:www\.)?[^:\/?\n]+)\:?(\d*)(\/[^?]*)?(\?.*)?", url, re.I)
    if re_match is not None:
        re_match = re_match.groups()
        domain = re_match[1] or ""
        return domain
    return url


def get_ip_addr(url):
    # remove protocol from URL (if exists)
    match_result = re.match(r"(?:.*\:\/\/)([^\/]*)", url)
    if match_result is not None:
        match_groups = match_result.groups()
        if len(match_groups) > 0:
            url = match_groups[0]

    # check if the url is already an IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", url):
        return url
    # dns lookup
    try:
        a = dns.resolver.resolve_name(url, family=socket.AF_INET)
        addrs = a.addresses()
        for addr in addrs:
            return addr
    except:
        print("Cannot resolve " + url)
        return None


# VirusTotal
def get_virustotal_data(url):
    api_base_url = 'https://www.virustotal.com/api/v3/urls/'
    vt_api_key = os.getenv("VT_API")  # VirusTotal API key - https://www.virustotal.com/
    # Headers with the API key
    headers = {
        'x-apikey': vt_api_key,
    }
    base_64_url = base64.b64encode(url.encode('ascii')) # encode the url in base64 bytes
    base_64_url = base_64_url.decode("ascii")  # get the base64 string
    base_64_url = base_64_url.rstrip('=')  # remove the trailing padding chars '='
    request_url = api_base_url + base_64_url

    try:
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


# BigDataCloud API (get location of IP address)
def get_dns_info(url):
    dns_api_key = os.getenv("DNS_API")  # BigDataCloud API key - https://www.bigdatacloud.com/
    api_base_url = "https://api.bigdatacloud.net/data/country-by-ip"
    ip_addr = get_ip_addr(url)
    if ip_addr is None:
        return "unknown"  # cannot resolve URL

    get_params = {
        "ip": ip_addr,
        "key": dns_api_key
    }
    request_url = api_base_url
    try:
        response = requests.get(request_url, params=get_params)  # Make the HTTP GET request

        # Check for a successful response (HTTP status code 200)
        if response.status_code == 200:
            # Access the JSON response
            result = response.json()
            # print (result)
        else:
            print(f"BigDataCloud Request failed with status code: {response.status_code}")
            result = {"country": "Unknown"}
        response.close()  # Close the response

        country = result["country"]
        if country is not None:
            # countryName = country["name"]  regionName = country["wbRegion"]["value"]
            countryID = country['isoAlpha3']  # country['isoName']
        else:
            countryID = "unknown"
            # countryName = "unknown"  regionName = "unknown"
        return countryID  # countryName, regionName
    except:
        return "unknown"


def get_url_info(url_to_analyze, string_out=False):
    url_fullhostname = get_fullhostname(url_to_analyze)  # gets the full host name (protocol + fqdn), w/o the URL path
    # url = get_hostname(url_to_analyze)
    vt_data = get_virustotal_data(url_fullhostname)
    domain_location = get_dns_info(url_fullhostname)

    url_info = {
        'Server location': domain_location,
        'VirusTotal scan': vt_data
    }
    if string_out:
        return str(url_info)
    else:
        return url_info


def get_simulated_values(percentile, location, label, false_positive=False):
    percentile = 100 if percentile > 100 else percentile  # cap it at 100
    if (label == 1 and not false_positive) or (label == 0 and false_positive):
        # "phishing" case OR "legit" false positive case
        harmless_count = 0
        undetected_count = round((100-percentile) * 0.28)  # RANGE FOR UNDETECTED [0-28] (28,21,14,7,0)
        malicious_count = round(percentile * 0.25)  # RANGE FOR MALICIOUS : [0-25] (0,6,12,19,25)
    else:  # if (label == 0 and not false_positive) or (label == 1 and false_positive):
        # "legit" case OR "phishing" false positive case
        harmless_count = round(percentile * 0.87)  # RANGE FOR HARMLESS [0-87] (0,22,43,65,87)
        undetected_count = round((100-percentile) * 0.28)  # RANGE FOR UNDETECTED [0-28] (28,21,14,7,0)
        malicious_count = 0
    vt_data = {'malicious': malicious_count, 'undetected': undetected_count,
               'harmless': harmless_count}

    return {
        'Server location': location,
        'VirusTotal scan': vt_data
    }
