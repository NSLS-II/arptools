# ARPTOOLS

| Distribution    | Build Status (master)                                                                                                                                                                                                                                   |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Overall Build   | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master)                                                    |
| Centos 8        | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20centos8)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master)        |
| Debian 10 amd64 | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20debian10_amd64)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master) |
| Debian 10 armhf | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20debian10_armhf)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master) |

## Installation

### RedHat

```bash
yum install libpcap-devel libnet-devel libconfig-devel mariadb-connector-c-devel systemd-devel cmake
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

interfaces = (
  {
    interface = "enp6s0";
    label = "subnet1";
    native_vlan = 100;
    networks = (
      {
        ipaddress = "192.168.1.1";
        subnet = "255.255.255.0";
        vlan = 101;
        src_ipaddress = "192.168.2.254";
      }
    )
  }, {
    interface = "enp4s0";
    label = "subnet2";
    networks = (
      {
        ipaddress = "10.10.0.0";
        subnet = "255.255.255.0";
        vlan = 0;
        src_ipaddress = "10.10.0.254";
      }
    )
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
| pcap_timeout     | microseconds | Packet buffer timeout in miliseconds (See PCAP)                             |
| filter_self      | bool         | If true, do not record MAC address of the interface used to monitor traffic |
| buffer_size      | int          | Size of internal ringbuffer for packet store                                |

### Interfaces Config Options

| Option         | Type   | Description                                                          |
|----------------|--------|----------------------------------------------------------------------|
| device         | string | Device name for the interface to listen on                           |
| label          | string | Label for this interface                                             |
| ignore_tagged  | bool   | If true, ignore tagged packets on this interface                     |
| native_vlan    | int    | The native VLAN tag for this interface to use when no tag is present |
| arp_requests   | int    | If true, send arp requests to the ipaddress range                    |
| arp_loop_delay | int    | Time in seconds to sleep between sending ARP requests                |
| arp_delay      | int    | Time in microseconds between ARP requestes from the same subnet      |

### Networks Config Options

| ipaddress        | string | IP Address for interface to use for sending ARP requests     |
|------------------|--------|--------------------------------------------------------------|
| subnet           | string | Subnet mask for ip addresses to use for sending ARP requests |
| vlan             | string | Subnet mask for ip addresses to use for sending ARP requests |
| vlan_pri         | string | Subnet mask for ip addresses to use for sending ARP requests |
| vlan_dei         | string | Subnet mask for ip addresses to use for sending ARP requests |
| vlan_dei         | string | Subnet mask for ip addresses to use for sending ARP requests |
| ipaddress_source | string | Subnet mask for ip addresses to use for sending ARP requests |
