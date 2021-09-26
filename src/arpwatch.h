//
//  arptools
//
//  Stuart B. Wilkins, Brookhaven National Laboratory
//
//
//  BSD 3-Clause License
//
//  Copyright (c) 2021, Brookhaven Science Associates
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
//  THE POSSIBILITY OF SUCH DAMAGE.
//
#ifndef SRC_ARPWATCH_H_
#define SRC_ARPWATCH_H_

#include "buffer.h"

#define ARPWATCH_CONFIG_FILE             "/etc/arpwatch.conf"
#define ARPWATCH_CONFIG_MAX_STRING       2048
// #define ARPWATCH_PCAP_PROGRAM            "(arp[6:2] = 2)"
// #define ARPWATCH_PCAP_PROGRAM            "arp"
#define ARPWATCH_PCAP_PROGRAM            "(ether broadcast) || arp"
#define ARPWATCH_PCAP_TIMEOUT            5
#define ARPWATCH_ARP_DELAY               50000
#define ARPWATCH_ARP_LOOP_DELAY          300
#define ARPWATCH_MYSQL_LOOP_DELAY        120
#define ARPWATCH_BUFFER_SIZE             10000

typedef struct {
  uint32_t ipaddress;
  uint32_t subnet;
  uint32_t ipaddress_source;
  int vlan;
  int vlan_pri;
  int vlan_dei;
} arpwatch_network;

typedef struct {
  int num_interface;
  int num_network;
  int mysql_loop_delay;
  int arp_delay;
  int arp_loop_delay;
  int pcap_timeout;
  int buffer_size;
  buffer_data data_buffer;
  int ignore_tagged;
  int arp_requests;
  int native_vlan;
  int *vlan_ignore;
  int num_vlan_ignore;
  char program[ARPWATCH_CONFIG_MAX_STRING];
  char device[ARPWATCH_CONFIG_MAX_STRING];
  char hostname[ARPWATCH_CONFIG_MAX_STRING];
  char username[ARPWATCH_CONFIG_MAX_STRING];
  char password[ARPWATCH_CONFIG_MAX_STRING];
  char database[ARPWATCH_CONFIG_MAX_STRING];
  char location[ARPWATCH_CONFIG_MAX_STRING];
  char label[ARPWATCH_CONFIG_MAX_STRING];
  char daemon_hostname[ARPWATCH_CONFIG_MAX_STRING];
  unsigned char hwaddress[ETH_ALEN];
  arpwatch_network *network;
} arpwatch_params;


#endif  // SRC_ARPWATCH_H_
