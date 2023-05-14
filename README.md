# CVEThreatScan
A simple threat scanner python script that checks for installed programs and corresponding vulnerabilities.

CVEThreatScan retrieves current user's installed programs on a Windows PC by checking relevant registry keys and then it checks for CVE vulnerabilities for each identified program by accessing the National Vulnerability Database (NVD) API provided by NIST.

Results are saved in a dedicated csv file at the end of the analysis.
