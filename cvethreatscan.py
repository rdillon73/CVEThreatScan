'''
cvethreatscan.py 
(c) 2023 Roberto Dillon - released under GPL 3.0


This Python script retrieves current user's installed programs on a Windows PC by checking relevant registry keys,
and creates a dictionary with program names and versions, which can be saved as a CSV file for reference if the user wants to.
Then it checks relevant CVE vulnerabilities for each identified program by accessing the
National Vulnerability Database (NVD) API provided by NIST.

To do so, the script uses the 'requests' module to send a search query to the NVD API for each program in the dictionary,
taking care of not exceeding the allowed request rate.
It then parses the JSON response and extracts the relevant CVE information (ID and URL) for each result, if any.
The script stores the CVE information in a new dictionary using the program name and version as the key.
Finally, the script writes the program and CVE information to a CSV file named after the current date and time.

Note that the script uses the bs4 module to extract the CVE URL from the NVD API response.

Note about False Positives and Negatives:
Including the version number in the search may miss a CVE that spans multiple versions (i.e. from v1.0 to v.3.0 and our program is v2.0), i.e. false negative.
Searching without the version, instead, may return CVE for older versions, i.e. false positive.
Doing both tests and checking for returned CVEs to see whether they are still valid for our specific program is recommended.


Reference:
https://nvd.nist.gov/developers/start-here
'''

import csv
import datetime
import requests
import winreg
from time import sleep
from bs4 import BeautifulSoup


def PrintIntro():
    print("========================================")
    print("=                                      =")
    print("=       cvethreatscan v.0.1.0          =")
    print("=         by Roberto Dillon            =")
    print("=     https://github.com/rdillon73     =") 
    print("=                                      =") 
    print("========================================")


PrintIntro()

# ask user for registry key to use
input_key = input("Enter u/U to check HKEY_CURRENT_USER (default) or m/M to check HKEY_LOCAL_MACHINE: ")
if (input_key == "M" or input_key == "m"):
    # Open the local machine's software registry key
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
else:
    # Open the current user's software registry key
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")

# ask if specific version should be included in the NIST search (may miss vulnerabilities that span multiple versions)
input_key = input("Enter v/V to include version field in NVD NIST search, n/N to include only program name (default): ")
if (input_key == "v" or input_key == 'V'):
    ver_check = 1
else:
    ver_check = 0

# ask if additional reference file listing programs and versions should be saved
input_key = input("Enter s/S to save an additional file with all found programs and their versions, n/N to skip (default): ")
if (input_key == "s" or input_key == 'S'):
    save_check = 1
else:
    save_check = 0


# Initialize an empty dictionary to store program names and versions
program_dict = {}

# Loop through all subkeys of the uninstall key
for i in range(winreg.QueryInfoKey(key)[0]):
    subkey_name = winreg.EnumKey(key, i)
    subkey = winreg.OpenKey(key, subkey_name)
    
    # Check if the subkey has a display name value
    try:
        display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
    except WindowsError:
        continue
    
    # now check for the version
    try:
        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
    except WindowsError:
        version = "Unknown"
    # Add the program name and version to the dictionary
    program_dict[display_name] = version

# Close the registry key
winreg.CloseKey(key)

# save the additional reference file, if requested
if save_check == 1:
    # Create a filename for the CSV file using the current date and time
    filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".csv"

    # Write the program dictionary to a CSV file
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        for program, version in program_dict.items():
            writer.writerow([program, version])

    print(f"List of detected Installed programs saved to {filename}")


# now check for relevant CVE vulnerabilities
# updated name for result file
filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S_CVE") + ".csv"

print("Now connecting to NVD NIST for checking any relevant vulnerability.\nThis may take several minutes...\n")

# Initialize an empty dictionary to store CVE vulnerabilities
cve_dict = {}

# Loop through all programs in the dictionary and check for relevant CVE vulnerabilities
for program, version in program_dict.items():
    # Build the search URL for the NVD API
    if ver_check == 1:
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={program} {version}"
    else:
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={program}"
        
    response = requests.get(url)
    
    # Parse the JSON response and extract the relevant CVE information
    data = response.json()
    for result in data['result']['CVE_Items']:
        cve_id = result['cve']['CVE_data_meta']['ID']
        cve_url = result['cve']['references']['reference_data'][0]['url']
        cve_dict[f"{program} {version}"] = (cve_id, cve_url)

    # have to wait: 5 requests for 30 seconds only are allowed by NIST 
    sleep(6)

# Write the program and CVE dictionaries to a CSV file
with open(filename, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Program Name", "Version", "CVE ID", "CVE URL"])
    for program, version in program_dict.items():
        cve_info = cve_dict.get(f"{program} {version}")
        if cve_info:
            writer.writerow([program, version, cve_info[0], cve_info[1]])
        else:
            writer.writerow([program, version, "nil", "nil"])

print(f"Programs and CVE list saved to {filename}")


