# ARPTOOLS

| Distribution  | Build Status (master)                                                                                                                                                                                                                             |
|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Overall Build | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master)                                              |
| Centos 7      | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20centos7)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master)  |
| Centos 8      | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20centos8)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master)  |
| Debian 10     | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20debian10)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master) |

## Installation

### RedHat

```bash
yum install libpcap-devel libnet-devel libconfig-devel mariadb-connector-c-devel libsystemd-devel cmake
mkdir build && cd build
cmake ..
make
make install
```

### Debian

```bash
apt install libmariadb-dev-compat libpcap-dev libnet-dev libconfig-dev libsystemd-dev cmake
mkdir build && cd build
cmake ..
make
make install
```

## Database Schema

[MySQL Database Schema](mysql/create_database.sql)

## Configuration

### Configuration file

```C
database = "arptools";
username = "arptools";
password = "password";
hostname = "localhost";
location = "eddie";

instances = (
  {
    interface = "enp6s0";
    ipaddress = "192.168.1.1";
    subnet = "255.255.255.0";
    label = "subnet1";
  }, {
    interface = "enp4s0";
    ipaddress = "10.10.0.0";
    subnet = "255.255.255.0";
    label = "subnet2";
  }
);
```

### Global config options

| Option           | Type         | Description                                                                 |
|------------------|--------------|-----------------------------------------------------------------------------|
| hostname         | string       | Hostname of MySQL Server                                                    |
| username         | string       | Username for connecting to MySQL server                                     |
| password         | string       | Password for connecting to MySQL server                                     |
| database         | string       | Database name                                                               |
| location         | string       | Location name to store in database                                          |
| mysql_loop_delay | int          | Time in seconds to sleep between MySQL Database transactions                |
| arp_loop_delay   | int          | Time in seconds to sleep between sending ARP requests                       |
| arp_delay        | int          | Time in microseconds between ARP requestes from the same subnet             |
| pcap_timeout     | microseconds | Packet buffer timeout in miliseconds (See PCAP)                             |
| filter_self      | bool         | If true, do not record MAC address of the interface used to monitor traffic |
| buffer_size      | int          | Size of internal ringbuffer for packet store                                |

### Instance config options

| Option        | Type   | Description                                                  |
|---------------|--------|--------------------------------------------------------------|
| interface     | string | Device name for the interface to listen on                   |
| label         | string | Label for this interface                                     |
| ipaddress     | string | IP Address for interface to use for sending ARP requests     |
| subnet        | string | Subnet mask for ip addresses to use for sending ARP requests |
| ignore_tagged | bool   | If true, ignore tagged packets on this interface             |
