# Cisco OpenVuln API Usage 

Scripts to get Cisco Security Advisories from Cisco using OpenVuln API

psirt_ssh.py - Connecs to devices via SSH. Identifies version, gets current PSIRT's using OpenVuln API and create Excel report.


## API Documentation

For more information about the openVuln API please visit: https://developer.cisco.com/psirt

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. 

### Prerequisites

Please create application and obtain CLIENT_SECRET and CLIENT_ID from https://apiconsole.cisco.com/ 


Python Requirements:
```
Python 3
Modules:
  Openpyxl
  Netmiko

```

### Installing

```
pip3 install -r requirements.txt
echo "CLIENT_ID = 'your_client_id'" >> config.py
echo "CLIENT_SECRET = 'your_client_secret'" >> config.py
```

### Input and Output

Input:
```
usage:python3.7 psirt_ssh.py [-h] --host HOST [--user USER] [--verbose] [--nxapi]

optional arguments:
  -h, --help   show this help message and exit
  --host HOST  hostname/ip address
  --user USER  Username
  --verbose    Enable Verbose Output
  --nxapi      Connect Using Cisco NX-OS NXAPI
```

Example: 
```
$ python3.7 psirt_ssh.py --host 192.168.123.236 --user admin 
Password: 
21:42:08: Connected (version 1.99, client Cisco-1.25)
21:42:09: Authentication (password) successful!
21:42:18: Connected (version 1.99, client Cisco-1.25)
21:42:19: Authentication (password) successful!
21:42:24: Getting PSIRT for IOSXE device. Version: 03.16.00.S
21:42:35: File: 192_168_123_236.xlsx was saved.
```

Output:
```
File hostname.xlsx will be created in working directory.
file contains:
AdvisoryID, Advisory Description, Advisory CVSS Score, Advisory URL
```


