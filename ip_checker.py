"""
A script for determining whether an IP address belongs to a country
"""
import os
import sys
import ntpath
import requests
import datetime
import argparse
from pathlib import Path


def source_file() -> Path:
    parser = argparse.ArgumentParser(usage="%(prog)s --file <path to file>",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--file", "-f", help="file with ip-addresses, where each address is on a new line")
    args = parser.parse_args()
    if args.file is not None:
        path_, basename_ = ntpath.split(args.file)
        if not path_:
            path_ = os.path.dirname(os.path.abspath(__file__))
        return Path(os.path.join(path_, basename_))
    else:
        sys.stderr.write(str(parser.print_help()))


if __name__ == "__main__":
    sf = source_file()

    try:
        sf.resolve(strict=True)
    except Exception as e:
        print(e)
    else:
        path_, basename_ = ntpath.split(sf)
        res_file = os.path.join(path_, basename_.replace(".txt", "_res.html"))
        num_lines = sum(1 for line in open(sf))

        collect = ''
        api_key = os.getenv("API_KEY")
        # https://docs.abuseipdb.com/#check-endpoint
        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {"Accept": "application/json", "Key": api_key, "Connection": "close"}

        with open(sf, "r") as s, open(res_file, "a") as d:
            for line_number, ip in enumerate([line.rstrip() for line in s]):
                params = {"ipAddress": ip, "maxAgeInDays": "90"}  # "verbose": "yes" }
                try:
                    r = requests.get(url=url, headers=headers, params=params)
                    if r and r.status_code == 200:
                        
                        if "countryName" in r.json():
                            print(f"{line_number+1}/{num_lines} - {ip} - {r.json()['data']['countryName']}")
                        else:
                            print(f"{line_number+1}/{num_lines} - {ip} - {r.json()['data']['countryCode']}")
                        
                        collect += f"<br><a href=\"https://abuseipdb.com/check/{ip}\" target=\"_blank\">ABUSEIPDB:</a><br>"
                        
                        for i in r.json()['data']:
                            if str(i) == "abuseConfidenceScore":
                                if r.json()['data'][i] > 79:
                                    collect += f"<span style=\"font-weight: 500;color: #f95656;\">{str(i)}: {str(r.json()['data'][i])}%</span><br>"
                                elif r.json()['data'][i] > 39 & r.json()['data'][i] < 80:
                                    collect += f"<span style=\"font-weight: 500;color: #ff9a3a;\">{str(i)}: {str(r.json()['data'][i])}%</span><br>"
                                elif r.json()['data'][i] > 0 & r.json()['data'][i] < 40:
                                    collect += f"<span style=\"font-weight: 500;color: #ffd000;\">{str(i)}: {str(r.json()['data'][i])}%</span><br>"
                                elif r.json()['data'][i] == 0:
                                    collect += f"<span style=\"font-weight: 500;color: #00ca86;\">{str(i)}: {str(r.json()['data'][i])}%</span><br>"
                            else:
                                collect += f"{str(i)}: {str(r.json()['data'][i])}<br>"
                    else:
                        try:
                            d.write(collect)
                            sys.stderr.write(str(r.json()) + "\n")
                        except (ValueError, KeyError):
                            d.write(collect)
                            sys.stderr.write(str(r.text) + "\n")
                except requests.exceptions.RequestException as e:
                    sys.stderr.write(str(e) + "\n")
            
            d.write(collect)
