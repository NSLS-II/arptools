# ARPTOOLS

| Distribution           | Build Status (master) |
| ---------------------- | ----------------------|
| Overall Build          | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master)|
| Centos 7               | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20centos7)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master) |
| Centos 8               | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20centos8)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master) |
| Debian 10              | [![Build Status](https://dev.azure.com/nsls-ii/arptools/_apis/build/status/NSLS-II.arptools?branchName=main&jobName=Build&configuration=Build%20debian10)](https://dev.azure.com/nsls-ii/arptools/_build/latest?definitionId=5&branchName=master) |

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

```json
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
