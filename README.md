# Scanhanced
Performs a network scan and then broadly finds vulnerabilities and exploits for services with found versions.

## Process
1. Run Nmap with version scanning.
2. Use detected versions to request CPE from NVD.
3. Use returned CPE to query for CVEs from NVD.
4. Use returned list of CVEs to query ExploitDB for exploits.
5. (Optional) Save vulnerable binaries, exploits, and/or output report to XML/JSON/CSV.


## WARNING:
> IT IS IMPORTANT TO NOTE THAT SCANNING A NETWORK WITHOUT PERMISSION MAY BE ILLEGAL. ALWAYS FIRST GET PERMISSION BEFORE SCANNING A NETWORK.

## Usage:
`python src/main.py [options] address`
### Options
| Flag                         | Meaning                            |
|------------------------------|------------------------------------|
| `-h/--help`                    | shows the options                  |
| `-v/--verbose`                 | shows verbose output               |
| `-s/--save-output`             | save printed output                |
| `-o/--output {csv, json, xml}` | generate output in specific format to _`./<date>-<time>-exploits.<type>`_ |
| `-d/--download`                | download found exploits to _`./exploits/<CVE>.txt`_           |
| `-b/--download-binary`         | download vulnerable binaries to _`./binaries/<Host IP>/<file>`_      |

### Example
`python src/main.py -v -b -d -o json scanme.nmap.org -s`
- `-v` - this will run _verbosely_
- `-b` - this will download vulnerable binaries if available
- `-d` - this will download any found exploits
- `-o json` - output to json file
- `scanme.nmap.org` - target to scan
- `-s` - save printed output

## **NOTE**
> Scanhanced casts a net as wide as possible and is very generous with version.
> This means that it is likely that many of the found vulnerabilities and exploits either don’t apply or don’t work. 
> Scanhanced is simply meant to compile a broad list of starting points that a pen tester can then use further for either manual verification, or automatic pipelines.

## _Potential_ Future Plans
- [ ] Create PyPi Package
- [ ] Create Docker Image
- [ ] Add additional exploit sources
- [ ] Improve version parsing
- [ ] Integrate with LLM API for short summaries or explanations for given CVE
