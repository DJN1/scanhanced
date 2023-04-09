import argparse
import json
import os
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


def run_nmap_version_scan(
    address: str, verbose: bool = False
) -> tuple[list, dict]:
    if verbose:
        print(f"Scanning {address} for open ports and versions")
    nmap = Nmap()
    results = nmap.nmap_version_detection(address, args="-Pn")
    host_list = [
        host
        for host in results.keys()
        if host not in ["runtime", "stats", "task_results"]
    ]
    return host_list, results


def get_cpes_from_service(
    service_name: str, service_version: str, service_cpe: str, verbose: bool
) -> str:
    if "/a" in service_cpe:
        cpe_search_term = f"cpe:2.3:a:{service_cpe.replace('cpe:/a:', '')}"
    if "/o" in service_cpe:
        cpe_search_term = f"cpe:2.3:o:{service_cpe.replace('cpe:/o:', '')}"
    if service_name == "OpenSSH" and "p" in service_version:
        p_index = cpe_search_term.index("p", -4, -1)
        cpe_search_term = cpe_search_term[:p_index]
    if service_name == "nginx" and "igor_sysoev" in service_cpe:
        cpe_search_term = cpe_search_term.replace("igor_sysoev", "f5")
    if verbose:
        print(
            f"Searching for CPE for {service_name} {service_version} with CPE {cpe_search_term}"
        )
    service_cpe = nvdlib.searchCPE(cpeMatchString=cpe_search_term)
    if len(service_cpe) == 0:
        return ""
    return service_cpe[0].cpeName


def get_exploits_for_cves(
    service_str: str, host: str, cve_list: list, download: bool, verbose: bool
) -> dict:
    service_exploits = {}
    for cve in cve_list:
        service_exploits[cve] = []
        res = requests.get(
            "https://www.exploit-db.com/search",
            params={"cve": cve},
            headers=EXPLOITDB_HEADERS,
        )
        if res.status_code == 200 and len(res.json()["data"]) > 0:
            # print(res.json()["data"])
            for exploit in res.json()["data"]:
                exploit_url = (
                    f"https://www.exploit-db.com/exploits/{exploit['id']}"
                )
                exploit_obj = {
                    "url": exploit_url,
                    "verified": bool(exploit["verified"]),
                }
                if len(exploit["tags"]) > 0:
                    for tag in exploit["tags"]:
                        if tag["title"] == "Metasploit Framework (MSF)":
                            exploit_obj["metasploit"] = True
                        else:
                            exploit_obj["metasploit"] = False
                else:
                    exploit_obj["metasploit"] = False
                if verbose:
                    print(
                        f"Found {'verified ' if exploit['verified'] else ''}exploit{'(Metasploit)' if exploit_obj['metasploit'] else ''} for {cve}"
                    )

                service_exploits[cve].append(exploit_obj)
                if download:
                    download_exploits(exploit["id"], cve, verbose)
        else:
            if verbose:
                print(f"No exploits found for {cve}")
        sleep(1)
    return service_exploits


def get_service_list_for_host(results: list, verbose: bool) -> list:
    service_list = []
    for result in results:
        service_name = ""
        service_version = ""
        service_cpe = ""
        if "version" in result["service"] and len(result["cpe"]) != 0:
            if "version" in result["service"]:
                service_name = result["service"]["product"]
                service_version = result["service"]["version"]
                if " " in service_version:
                    service_version = service_version.split(" ")[0]
                if verbose:
                    print(f"Found Service: {service_name} {service_version}")
                service_cpe = result["cpe"][0]["cpe"]
            service_list.append(
                {
                    "service_name": service_name,
                    "version": service_version,
                    "cpe": service_cpe,
                    "port": result["portid"],
                }
            )
    return service_list


def download_exploits(exploit_id: str, cve: str, verbose: bool):
    if verbose:
        print(f"Downloading exploit {exploit_id}")
    res = requests.get(
        f"https://www.exploit-db.com/download/{exploit_id}",
        headers=EXPLOITDB_HEADERS,
    )
    if res.status_code == 200:
        try:
            if not os.path.exists("exploits"):
                if verbose:
                    print("Creating exploits directory")
                os.mkdir("exploits")
            if not os.path.exists(f"exploits/{cve}-{exploit_id}.txt"):
                if verbose:
                    print(f"Saving exploit {exploit_id} to file")
                with open(f"exploits/{cve}-{exploit_id}.txt", "wb") as f:
                    f.write(res.content)
        except Exception as e:
            print(e)
            exit(1)
    sleep(1)


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
    parser.add_argument(
        "-s",
        "--save-output",
        dest="save_output",
        action="store_true",
        help="save console output to file",
    )
    parser.add_argument(
        "-d",
        "--download",
        dest="download",
        action="store_true",
        help="download found exploits",
    )
    args = parser.parse_args()
    host_list, results = run_nmap_version_scan(args.address, args.verbose)
    exploit_search_results = {}
    for host in host_list:
        exploit_search_results[host] = {}
        results_list = results[host]["ports"]
        service_list = get_service_list_for_host(results_list, args.verbose)
        for service in service_list:
            exploit_search_results[host][
                f"{service['service_name']} {service['version']}"
            ] = {"port": service["port"]}
        for service in service_list:
            service_cpe_name = get_cpes_from_service(
                service["service_name"],
                service["version"],
                service["cpe"],
                args.verbose,
            )
            if service_cpe_name == "":
                pass
            else:
                service_cves = [
                    cve.id
                    for cve in nvdlib.searchCVE(cpeName=service_cpe_name)
                ]
                exploit_search_results[host][
                    f"{service['service_name']} {service['version']}"
                ].update(
                    get_exploits_for_cves(
                        f"service['service_name'] {service['version']}",
                        host,
                        service_cves,
                        args.download,
                        args.verbose,
                    )
                )
        if args.output:
            output(exploit_search_results, args.output)
        for host in exploit_search_results.keys():
            output_str = f"{host}\n"
            if len(exploit_search_results[host].keys()) == 0:
                output_str += "\tNo vulnerabilities found\n"
            else:
                for service in exploit_search_results[host].keys():
                    printed = False
                    if len(exploit_search_results[host][service].keys()) == 0:
                        output_str += f"\t{service} - Port: {exploit_search_results[host][service]['port']}\n"
                        output_str += "\t\tNo vulnerabilities found\n"
                    else:
                        for cve in exploit_search_results[host][
                            service
                        ].keys():
                            if not printed:
                                output_str += f"\t{service} - Port: {exploit_search_results[host][service]['port']}\n"
                                printed = True
                            if (
                                cve != "port"
                                and len(
                                    exploit_search_results[host][service][cve]
                                )
                                > 0
                            ):
                                output_str += f"\t\t{cve}\n"
                                for exploit in exploit_search_results[host][
                                    service
                                ][cve]:
                                    output_str += f"\t\t\t{exploit['url']}{' (Metasploit)' if exploit['metasploit'] else ''}"
                                    if exploit["verified"]:
                                        output_str += " - Verified"
                                    output_str += "\n"
                    output_str += "\n"
            print(output_str)
            if args.save_output:
                with open(
                    f"nvs-{args.address.replace('.', '_')}-output.txt", "a"
                ) as f:
                    f.write(output_str)


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
                                f"{host},{service.replace(' ', '_')},{cve},{exploit['url']}\n"
                            )
    else:
        pass


if __name__ == "__main__":
    main()
