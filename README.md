# Cisco OpenVuln API Usage 

Scripts to get Cisco Security Advisories from Cisco using OpenVuln API

psirt_ssh.py - Connecs to devices via SSH. Identifies version and get current PSIRT using OpenVuln API

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



