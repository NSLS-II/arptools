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

#ifndef SRC_CAPTURE_H_
#define SRC_CAPTURE_H_

#include <net/ethernet.h>
#include <pcap.h>

#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q       0x8100
#endif

#define DHCP_SNLEN                  64
#define DHCP_BFLEN                  128
#define IP_PROTO_UDP                0x11
#define DHCP_DISCOVER_SPORT         68
#define DHCP_DISCOVER_DPORT         67
#define DHCP_HWLEN                  16
#define DHCP_OPCODE_HOSTNAME        12
#define DHCP_OPCODE_MESSAGE_TYPE    53
#define DHCP_OPCODE_END             255
#define NETBIOS_NAMELEN             32
#define NETBIOS_PORT                137
#define EPICS_DPORT                 5064
#define EPICS_PVA_DPORT             5076

struct ethernet_header {
  uint8_t ether_dhost[ETH_ALEN];
  uint8_t ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__((__packed__));

struct ethernet_header_8021q {
  uint8_t ether_dhost[ETH_ALEN];
  uint8_t ether_shost[ETH_ALEN];
  uint16_t tpid;
  uint16_t tci;
  uint16_t ether_type;
} __attribute__((__packed__));

struct arpbdy {
  unsigned char ar_sha[ETH_ALEN];
  struct in_addr ar_sip;
  unsigned char ar_tha[ETH_ALEN];
  struct in_addr ar_tip;
} __attribute__((__packed__));

struct ipbdy {
  uint8_t  ver_ihl;          // Version (4 bits) + header (4 bits)
  uint8_t  tos;              // Type of service
  uint16_t tlen;             // Total length
  uint16_t identification;   // Identification
  uint16_t flags_fo;         // Flags (3 bits) + Fragment offset (13 bits)
  uint8_t  ttl;              // Time to live
  uint8_t  proto;            // Protocol
  uint16_t crc;              // Header checksum
  struct in_addr ip_sip;     // Source address
  struct in_addr ip_dip;     // Destination address
  // uint32_t op_pad;           // Option + Padding
} __attribute__((__packed__));

struct udphdr {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t checksum;
} __attribute__((__packed__));

struct dhcpbdy {
  uint8_t op;                        // Operation Code
  uint8_t htype;                     // Hardware Type (same as ARP)
  uint8_t hlen;                      // Hardware Address Length
  uint8_t hops;                      // Hops for forwarding
  uint32_t xid;                      // Transaction Identifier
  uint16_t secs;                     // Seconds (Seconds since attempt)
  uint16_t flags;                    // Broadcast Flag
  struct in_addr ip_cip;             // Client IP Address
  struct in_addr ip_yip;             // Your IP Address
  struct in_addr ip_sip;             // Server IP Address
  struct in_addr ip_gip;             // Gateway IP Address
  uint8_t hwaddr[ETH_ALEN];          // Client HW Address
  uint8_t hwaddr_padding[DHCP_HWLEN - ETH_ALEN];  // Padding
  char server_name[DHCP_SNLEN];      // Server Name
  char boot_filename[DHCP_BFLEN];    // Boot Filename
  uint32_t cookie;                   // Magic Cookie
} __attribute__((__packed__));

struct netbioshdr {
  uint16_t trans_id;
  uint16_t flags;
  uint16_t n_queries;
  uint16_t n_answer;
  uint16_t n_authority;
  uint16_t n_additional;
} __attribute__((__packed__));

struct netbiosbdy {
  uint8_t len;
  char name[NETBIOS_NAMELEN];
  char zero;
  uint16_t type;
  uint16_t _class;
} __attribute__((__packed__));

struct ca_proto_msg {
  uint16_t command;
  uint16_t payload_size;
  uint16_t data;
  uint16_t count;
  uint32_t param1;
  uint32_t param2;
} __attribute__((__packed__));

struct ca_proto_search {
  uint16_t command;
  uint16_t payload_size;
  uint16_t reply;
  uint16_t version;
  uint32_t cid1;
  uint32_t cid2;
} __attribute__((__packed__));

int capture_start(arpwatch_params *params);
int capture_stop(void);

#endif  // SRC_CAPTURE_H_
