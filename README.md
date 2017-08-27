# :mute: Low-Impact Fingerprint Tool 

Quietly **"lift"** fingerprints from devices by using their SSL certificates, HTTP headers or other characteristics.

**Requires Python 2.7.10 or higher**


This project requires Python 2.7.10 or higher because of the massive changes to the ssl library. Python 2.7.10 introduced the SSLContext class to help sophisticated applications (like lift) manage settings and certificates.

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

1. Download the project

```
$ git clone git@github.com:trylinux/lift.git
$ cd lift
```

2. Create a virtual environment   

For Python2   

```
$ virtualenv -p python venv
$ source venv/bin/activate
```
For Python3   

```
$ python3 -m venv venv
$ source venv/bin/activate
```
3. Install the project's dependencies in a virtual environment   

For Python2   

```
$ pip install -r requirements.txt
```
For Python3   

```
$ python -m pip install -r lift/requirements.txt 
```
### Examples

The best way to use this tool is to run the following:   

For Python2   

```
$ python lift.py -f <file_with_one_ip_per_line> -I 
```
For Python3 (Scapy must be run with root priviledges.)   

```
$ sudo python -m lift.lift -i <ip_address> -p <port_number> 
```
Only one of the required arguments can be supplied when running the lift tool.

**Required Arguments**:

- **-f** &nbsp;&nbsp; or &nbsp;&nbsp; **--ipfile** &nbsp;&nbsp;&nbsp;&nbsp; `filename` - file with one IP address per line
- **-s** &nbsp;&nbsp; or &nbsp;&nbsp; **--subnet** &nbsp;&nbsp;&nbsp;&nbsp;`string` -  the IP address range of a subnet
- **-i** &nbsp;&nbsp; or &nbsp;&nbsp; **--ip** &nbsp;&nbsp;&nbsp;&nbsp;`string` - a single IP address
- **-a** &nbsp;&nbsp; or  &nbsp;&nbsp; **--asn** &nbsp;&nbsp;&nbsp;&nbsp; `integer` - The officially registered autonomous system number (ASN) of an internet service provider (ISP)

**Optional Arguments**:
- **-p** &nbsp;&nbsp; or &nbsp;&nbsp; **--port**  `integer` - The port number at the supplied IP address that lift should connect to.
- **--recurse** - Test Recursion
- **--recon**   - Gather information about a given device.
- **-o** &nbsp;&nbsp; or &nbsp;&nbsp; **--outfile**  `filename` - Where to write the results of this IP scanning.
- **-t** &nbsp;&nbsp; or &nbsp;&nbsp; **--num-threads**  `integer` - instead of checking 1 IP address at a time, check this many IP addresses concurrently.


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

- Write a tool for adding signatures in a standard fashion. In doing so, users of lift can supply their own list of indicators that lift will use when checking the IP addresses.

- Design ways to implement the features that are presently not used -- testing for UDP, DNS, SSDP and NTP amplification abilities on remote devices.

- Modify lift to be compatible with [nmap](https://nmap.org/)


#### Bugs

- There are some weird bugs with some of the recursive checks.


## License

???? - Zachary Wikholm