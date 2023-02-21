import requests
import urllib
import json

def check(url):
    encoded_url = urllib.parse.quote(url, safe='')
    api_url = "https://ipqualityscore.com/api/json/url/dES6QOilFVi76vD6KlzjzjC74zSRHur0/"
    data = requests.get(api_url + encoded_url)
    decoded_data = json.loads(data)
    
    safe = False
    
    if decoded_data["unsafe"] == "false":
        if decoded_data["suspicious"] == "false":
            if decoded_data["phishing"] == "false":
                if decoded_data["malware"] == "false":
                    if decoded_data["spamming"] == "false":
                        safe = True
    
    return safe