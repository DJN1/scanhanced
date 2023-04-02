import argparse
import json
from datetime import datetime
from enum import Enum
from time import sleep

import nvdlib
import requests
from dict2xml import dict2xml
from nmap3 import Nmap


class OutputFormat(Enum):
    XML = "xml"
    JSON = "json"
    CSV = "csv"


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
    parser.add_argument("address", type=str, help="the address to scan")
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="print verbose output",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        choices=[enum.value for enum in OutputFormat],
        help="generate output file in specified format",
    )
    args = parser.parse_args()
    print("starting nmap")

    nmap = Nmap()
    results = nmap.nmap_version_detection(args.address, args="-Pn")
    host_list = [
        host
        for host in results.keys()
        if host not in ["runtime", "stats", "task_results"]
    ]
    exploit_search_results = {}
    for host in host_list:
        exploit_search_results[host] = {}
        results_list = results[host]["ports"]
        service_list = []
        for result in results_list:
            service_name = ""
            service_version = ""
            service_cpe = ""
            if "version" in result["service"] and len(result["cpe"]) != 0:
                if "version" in result["service"]:
                    service_name = result["service"]["product"]
                    service_version = result["service"]["version"]
                    if " " in service_version:
                        service_version = service_version.split(" ")[0]
                    if args.verbose:
                        print(
                            f"Found Service: {service_name} {service_version}"
                        )
                    service_cpe = result["cpe"][0]["cpe"]
                service_list.append(
                    {
                        "service_name": service_name,
                        "version": service_version,
                        "cpe": service_cpe,
                        "port": result["portid"],
                    }
                )
        for service in service_list:
            exploit_search_results[host][
                f"{service['service_name']} {service['version']}"
            ] = {"port": service["port"]}
        service_exploits = []
        for service in service_list:
            cpe_search_term = (
                f"cpe:2.3:a:{service['cpe'].replace('cpe:/a:', '')}"
            )
            if (
                service["service_name"] == "OpenSSH"
                and "p" in service["version"]
            ):
                cpe_search_term = service["cpe"].replace("cpe:/a:", "")
                cpe_search_term = (
                    f"cpe:2.3:a:{cpe_search_term[:-4]}:{cpe_search_term[-2:]}"
                )
            service_cpe = nvdlib.searchCPE(cpeMatchString=cpe_search_term)
            service_cves = [
                cve.id
                for cve in nvdlib.searchCVE(cpeName=service_cpe[0].cpeName)
            ]
            for cve in service_cves:
                exploit_search_results[host][
                    f"{service['service_name']} {service['version']}"
                ][cve] = []
                res = requests.get(
                    "https://www.exploit-db.com/search",
                    params={"cve": cve},
                    headers=EXPLOITDB_HEADERS,
                )
                if res.status_code == 200 and len(res.json()["data"]) > 0:
                    if args.verbose:
                        print(f"Found exploit for {cve}")
                    for exploit in res.json()["data"]:
                        exploit_url = f"https://www.exploit-db.com/exploits/{exploit['id']}"
                        exploit_search_results[host][
                            f"{service['service_name']} {service['version']}"
                        ][cve].append(exploit_url)
                        service_exploits.append(
                            {"CVE": cve, "link": exploit_url}
                        )
                else:
                    if args.verbose:
                        print(f"No exploits found for {cve}")
                sleep(1)
        if args.output:
            output(exploit_search_results, args.output)
        for host in exploit_search_results.keys():
            print(host)
            for service in exploit_search_results[host].keys():
                printed = False
                for cve in exploit_search_results[host][service].keys():
                    if not printed:
                        print(
                            f"\t{service} - Port: {exploit_search_results[host][service]['port']}"
                        )
                        printed = True
                    if cve != "port" and len(exploit_search_results[host][service][cve]) > 0:
                        print(f"\t\t{cve}")
                        for exploit in exploit_search_results[host][service][
                            cve
                        ]:
                            print(f"\t\t\t{exploit}")


def output(results, format):
    if format == OutputFormat.XML.value:
        filename = str(datetime.now()).replace(" ", "_") + "-exploits.xml"
        with open(filename, "w") as f:
            f.write(dict2xml(results))
    elif format == OutputFormat.JSON.value:
        filename = str(datetime.now()).replace(" ", "_") + "-exploits.json"
        json.dump(results, open(filename, "w"))
    elif format == OutputFormat.CSV.value:
        filename = str(datetime.now()).replace(" ", "_") + "-exploits.csv"
        with open(filename, "w") as f:
            for host in results.keys():
                for service in results[host].keys():
                    for cve in results[host][service].keys():
                        for exploit in results[host][service][cve]:
                            f.write(
                                f"{host},{service.replace(' ', '_')},{cve},{exploit}\n"
                            )
    else:
        pass


if __name__ == "__main__":
    main()
