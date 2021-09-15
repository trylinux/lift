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

1. Download the project

```
$ git clone https://github.com/trylinux/lift.git
$ cd lift
```

2. Create a virtual environment

```
$ python3 -m venv venv
$ source venv/bin/activate
```

3. Install the project's dependencies in a virtual environment

```
$ pip3 install -r requirements.txt
```

### Examples

The best way to use this tool is to run 

```
$ python lift.py -f <file_with_one_ip_per_line>  
```

For shodan input and to send to an output file 

```
$ python lift.py -f <shodan_json_file> -t shodan -o outputfile.txt
```


Only one of the required arguments can be supplied when running the lift tool.

**Required Arguments**:

- **-f** &nbsp;&nbsp; or &nbsp;&nbsp; **--ifile** &nbsp;&nbsp;&nbsp;&nbsp; `filename` - file with one IP address per line
- **-s** &nbsp;&nbsp; or &nbsp;&nbsp; **--subnet** &nbsp;&nbsp;&nbsp;&nbsp;`string` -  the IP address range of a subnet
- **-i** &nbsp;&nbsp; or &nbsp;&nbsp; **--ip** &nbsp;&nbsp;&nbsp;&nbsp;`string` - a single IP address

**Optional Arguments**:
- **--p** &nbsp;&nbsp; or &nbsp;&nbsp; **--port**  `integer` - The port number at the supplied IP address that lift should connect to.
- **-o** &nbsp;&nbsp; or &nbsp;&nbsp; **--ofile**  `filename` - The output file for the results. If it does exist, it'll be overwritten. If it doesn't exist, it'll be created
- **-t** &nbsp;&nbsp; or &nbsp;&nbsp; **--filetype** `file type` - This is the format of the input file. LIFT takes a list of IPs (one per line) by default, but understands Shodan json files and files with <ip>:<port> (still one per line)


Several arguments have been removed for the time being, including -v, -I and -r. 


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
