# Low-Impact Fingerprint Tool

Quietly **"lift"** fingerprints from devices by using their SSL certificates, HTTP headers or other characteristics.

**Requires Python 3 or higher**
**BEST IF USED WITH PYTHON 3**



## Table of Contents

- [Introduction](#introduction)
  - [Why lift?](#why-lift)
  - [How It Works](#how-it-works)
    - [Identify the device using SSL Certificates](#identify-the-device-using-ssl-certificates)
    - [Identify the device using HTTP Headers and Response](#identify-the-device-using-http-headers-and-response)
- [Usage](#usage)
  - [Installation](#installation)
  - [Examples](#examples)
- [Documentation and Support](#documentation-and-support)
  - [Needs](#needs)
  - [Enhancements](#enhancements)
  - [Features](#features)
  - [Bugs](#bugs)
- [License](#license)



## Introduction

### Why lift?

Lift is all about getting a slightly less fuzzy idea about what a device is based on characteristics that are uniform across all the devices and unique to them at the same time. It tries to identify a device while making as few HTTP requests as possible, and cautiously avoids alerting the device to lift's detective work. Although lift isn't capable of detecting a piece of hardware's serial number, in rare cases it has identified the firmware version of a device.

### How It Works


#### Identify the device using SSL Certificates

1. Lift negotiates a SSL/TLS socket connection to the device's IP address, but never actually makes a request. In doing so, lift does not generate a log on the device that you are trying to detect. 


2. It then compares the device's SSL certificate against lift's collection of certificates, and returns any device names that tend to match that certificate.


#### Identify the device using HTTP Headers and Response

1. If lift doesn't find this device's certificate in its collection OR if the device does not have a certificate, lift makes a single HTTP GET request on port 443 and then another on port 80. 


2. In most cases, lift can uniquely identify the device by parsing the server version from the HTTP Headers and/or the body of the response's resource.
One router manufacturer even puts the firmware version number in the title of the HTTP response's resource!


## Usage

### Installation

1) Download the project...

```
$ git clone https://github.com/trylinux/lift.git
$ cd lift
```

2) Create a virtual environment...

```
$ virtualenv -p python3 venv
$ source venv/bin/activate
```

3) Install Lift in the virtual environment...

```
$ python3 setup.py develop
```

### Examples

The simplest way to use this tool is to run the following...

WARNING: Scanning port 443 does SSL checks and is known to be slow and have bugs.

```
$ lift -f <file_with_one_ip_per_line> -p 80 -p 443 -o outputfile.txt
```

For shodan input and to send to an output file...

```
$ lift -f <shodan_json_file> -t shodan -p 80 -p 443 -o outputfile.txt
```

**Usage**:

```
usage: lift [-h] [-v] [-c CONCURRENCY] [-i IP] [-s SUBNET] [-f IFILE] [-p PORT] [-t {standard,withport,shodan}] [-S] [-r] [-R] [-o OFILE] [-e EFILE]

Low Impact Identification Tool

options:
  -h, --help            show this help message and exit
  -v, --verbose         specifies the output verbosity (can specify multiple times)
  -c CONCURRENCY, --concurrency CONCURRENCY
                        specifies how many concurrent scans to run
  -i IP, --ip IP        specifies an IP address to scan (can specify multiple times)
  -s SUBNET, --subnet SUBNET
                        specifies a CIDR subnet to scan (can specify multiple times)
  -f IFILE, --ifile IFILE
                        specifies a file containing targets to scan
  -p PORT, --port PORT  specifies a port to scan (can specify multiple times)
  -t {standard,withport,shodan}, --filetype {standard,withport,shodan}
                        specifies the format of the --ifile argument
  -S, --ssl             do SSL checks only
  -r, --recurse         test for recursion and amplification
  -R, --recon           run all tests
  -o OFILE, --ofile OFILE
                        specifies the output file (optional)
  -e EFILE, --efile EFILE
                        specifies the error file (default: lift.error)
```

## Documentation and Support

If you want more signatures added to lift's collection of certificates, please note your request in this project's [Issues tracker](https://github.com/trylinux/lift/issues). The lift tool is still in under development and will be for some time. Keep your eyes open for changes!

-ZW

### Want to help?


#### Needs

- **Testing** 

  - Create test classes and methods that use dummy versions of the actual data that is returned when negotiating SSL/TLS handshakes or making GET requests. It might be useful to use [scapy](http://www.secdev.org/projects/scapy/build_your_own_tools.html) when implementing the tests.

- **Validation**

  - The project needs better input validation of the command line arguments.

#### Enhancements

- Use [setuptools](https://setuptools.readthedocs.io/en/latest/) to make it easier for new users to install lift and its dependencies.

- Provide more detailed usage examples and supply samples of all the possible command line input arguments (i.e. ifile, ip, asn and subnet) to demonstrate more clearly how the tool should be used. 

- Add more input sanitizing so future users of the lift tool don’t have to worry about formatting the input file of IPs before supplying it as a command line argument.

#### Features

- Apply asynchronous programming concepts and/or parallelization techniques (multi-threading) to speed up the slow task of checking each IP address.

- Write a tool for adding signatures in a standard fashion. In doing so, users of lift can supply their own list of indicators against which lift will compare the devices that it checks.

## Contact

- If you want to talk to me about this, please send an email to kestrellift@gmail.com

- https://www.patreon.com/liftproject

## License

???? - Zachary Wikholm
