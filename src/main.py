import argparse
import json
from time import sleep

import nvdlib
import requests
from nmap3 import Nmap

EXPLOITDB_HEADERS = {
    "Accept": "application/json",
    "X-Requested-With": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:110.0) Gecko/20100101 Firefox/110.0",
}


def main():
    parser = argparse.ArgumentParser(
        prog="NVS",
        description="Scans given address for versions and scrapes vulnerabilties for found versions",
    )
    parser.add_argument("address", type=str)
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true")
    args = parser.parse_args()
    print("starting nmap")
    nmap = Nmap()
    results = nmap.nmap_version_detection(args.address)
    # print(results)
    results_list = results[list(results.keys())[0]]["ports"]
    # print(results_list)
    service_list = []
    for result in results_list:
        service_name = ""
        service_version = ""
        service_cpe = ""
        if "version" in result["service"] and len(result["cpe"]) != 0:
            if "version" in result["service"]:
                service_name = result["service"]["product"]
                service_version = result["service"]["version"][
                    0 : result["service"]["version"].find(" ", 0, -1)
                ]
                if args.verbose:
                    print(f"Found Service: {service_name} {service_version}")
                service_cpe = result["cpe"][0]["cpe"]
            service_list.append(
                {
                    "service_name": service_name,
                    "version": service_version,
                    "cpe": service_cpe,
                }
            )

    service_exploits = []
    for service in service_list:
        cpe_search_term = f"cpe:2.3:a:{service['cpe'].replace('cpe:/a:', '')}"
        if service["service_name"] == "OpenSSH" and "p" in service["version"]:
            cpe_search_term = service["cpe"].replace("cpe:/a:", "")
            cpe_search_term = (
                f"cpe:2.3:a:{cpe_search_term[:-4]}:{cpe_search_term[-2:]}"
            )
        service_cpe = nvdlib.searchCPE(cpeMatchString=cpe_search_term)
        service_cves = [
            cve.id for cve in nvdlib.searchCVE(cpeName=service_cpe[0].cpeName)
        ]
        for cve in service_cves:
            res = requests.get(
                "https://www.exploit-db.com/search",
                params={"cve": cve},
                headers=EXPLOITDB_HEADERS,
            )
            if res.status_code == 200 and len(res.json()["data"]) > 0:
                if args.verbose:
                    print(f"Found exploit for {cve}")
                for exploit in res.json()["data"]:
                    service_exploits.append(
                        {
                            "CVE": cve,
                            "link": f"https://www.exploit-db.com/exploits/{exploit['id']}",
                        }
                    )
            else:
                if args.verbose:
                    print(f"No exploits found for {cve}")
            sleep(1)
    print(service_exploits)


if __name__ == "__main__":
    main()
