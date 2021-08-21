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

#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

#include "buffer.h"
#include "debug.h"
#include "arpwatch.h"
#include "capture.h"
#include "utils.h"

pcap_t *pcap_description = NULL;

unsigned char mac_zeros[] = {0, 0, 0, 0, 0, 0};
unsigned char mac_bcast[] = {255, 255, 255, 255, 255, 255};

int dhcp_message_type[] = {0,  // Padding, no zero msg type
                           BUFFER_TYPE_DHCP_DISCOVER,
                           BUFFER_TYPE_DHCP_OFFER,
                           BUFFER_TYPE_DHCP_REQUEST,
                           BUFFER_TYPE_DHCP_DECLINE,
                           BUFFER_TYPE_DHCP_ACK,
                           BUFFER_TYPE_DHCP_NACK,
                           BUFFER_TYPE_DHCP_RELEASE };

int ether_header_size(const u_char *packet) {
  struct ethernet_header *hdr = (struct ethernet_header *)packet;
  if (ntohs(hdr->ether_type) == ETHERTYPE_8021Q) {
    // Tagged packet
    return sizeof(struct ethernet_header_8021q);
  } else {
    return sizeof(struct ethernet_header);
  }
}

uint16_t ether_get_vlan(arpwatch_params *params, const u_char *packet) {
  struct ethernet_header *hdr = (struct ethernet_header *)packet;

  uint16_t vlan = params->native_vlan;
  if (ntohs(hdr->ether_type) == ETHERTYPE_8021Q) {
    struct ethernet_header_8021q *vlan_hdr =
      (struct ethernet_header_8021q *)packet;
    vlan = ntohs(vlan_hdr->tci) & 0x0FFF;

    DEBUG_PRINT("VLAN Tag = %d\n", vlan);
  }

  return vlan;
}

int capture_ethernet_packet(arpwatch_params *params,
                            const struct pcap_pkthdr* pkthdr,
                            const u_char* packet) {
  struct ether_header *eptr = (struct ether_header *) packet;

#ifdef DEBUG
  uint16_t type = ntohs(eptr->ether_type);

  DEBUG_PRINT("ETHERNET Packet type %d (0x%0X) from %s\n",
              type, type,
              ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
#endif

  buffer_data *data = &params->data_buffer;
  arp_data *d = buffer_get_head(data);

  d->type = BUFFER_TYPE_UNKNOWN;
  memcpy(d->hw_addr, eptr->ether_shost, ETH_ALEN);
  d->ts = pkthdr->ts;

  // Set DHCP to NULL

  *(d->dhcp_name) = '\0';

  // Set IP Address to zero

  struct in_addr zero;
  zero.s_addr = 0;
  d->ip_addr = zero;
  d->vlan = ether_get_vlan(params, packet);

  buffer_advance_head(data, 1);

  return 0;
}

int ether_arp_is_ipv4(const struct arphdr *aptr) {
  if (ntohs(aptr->ar_pro) != 0x0800) {
    return 0;
  }

  if (ntohs(aptr->ar_hrd) != ARPHRD_ETHER) {
    return 0;
  }

  if (aptr->ar_hln != ETH_ALEN) {
    return 0;
  }

  if (aptr->ar_pln != sizeof(struct in_addr)) {
    return 0;
  }

  return -1;
}

int capture_arp_packet(arpwatch_params *params,
                       const struct pcap_pkthdr* pkthdr,
                       const u_char* packet) {
  struct ethernet_header *eptr = (struct ethernet_header *)packet;
  struct arphdr *aptr = (struct arphdr *)(packet +
                         ether_header_size(packet));
  struct arpbdy *bptr;

  if (!ether_arp_is_ipv4(aptr)) {
    ERROR_PRINT("%s : Non IPV4 ARP Packet\n", params->device);

    buffer_data *data = &params->data_buffer;
    arp_data *d = buffer_get_head(data);
    d->type = BUFFER_TYPE_UNKNOWN;
    memcpy(d->hw_addr, eptr->ether_shost, ETH_ALEN);
    d->ts = pkthdr->ts;
    *(d->dhcp_name) = '\0';
    d->vlan = ether_get_vlan(params, packet);
    buffer_advance_head(data, 1);

    return 0;
  }

  // A Valid IPV4 ARP Packet

  buffer_data *data = &params->data_buffer;

  if ((htons(aptr->ar_op) != ARPOP_REPLY) &&
      (htons(aptr->ar_op) != ARPOP_REQUEST)) {
    DEBUG_PRINT("Invalid ARP operation 0x%02X\n", htons(aptr->ar_op));
    return 0;
  }

  bptr = (struct arpbdy *) (packet +
                            ether_header_size(packet) +
                            sizeof(struct arphdr));

  //
  // Check for ARP Probes
  // ARP Probes have the source IP Address set to all zeros
  //
  if ((bptr->ar_sip.s_addr == 0) &&
      !memcmp(bptr->ar_tha, mac_zeros, ETH_ALEN)) {
    // ARP Probe!
    DEBUG_PRINT("Iface : %s Packet time : %ld ARP PROBE :  %-20s %-16s\n",
                params->device,
                pkthdr->ts.tv_sec,
                ether_ntoa((const struct ether_addr *)&bptr->ar_sha),
                inet_ntoa(bptr->ar_sip));

    arp_data *d = buffer_get_head(data);
    d->type = BUFFER_TYPE_ARP_PROBE;
    d->ip_addr = bptr->ar_tip;
    memcpy(d->hw_addr, bptr->ar_sha, ETH_ALEN);
    d->ts = pkthdr->ts;
    *(d->dhcp_name) = '\0';
    d->vlan = ether_get_vlan(params, packet);
    buffer_advance_head(data, 1);

    return 0;
  }

  //
  // Check for Gratuitous ARP Requests
  // These have Sender IP == Destination IP
  // Target MAC Will be set to zeros or FF
  // Reply can have THA == SHA
  //

  if ((bptr->ar_sip.s_addr == bptr->ar_tip.s_addr) &&
      (!memcmp(bptr->ar_tha, mac_bcast, ETH_ALEN) ||
       !memcmp(bptr->ar_tha, mac_zeros, ETH_ALEN) ||
       !memcmp(bptr->ar_sha, bptr->ar_tha, ETH_ALEN))) {
    DEBUG_PRINT("Iface : %s Packet time : %ld ARP GRAT :  %-20s %-16s\n",
                params->device,
                pkthdr->ts.tv_sec,
                ether_ntoa((const struct ether_addr *)&bptr->ar_sha),
                inet_ntoa(bptr->ar_sip));

    arp_data *d = buffer_get_head(data);
    d->type = BUFFER_TYPE_ARP_GRAT;
    d->ip_addr = bptr->ar_sip;
    memcpy(d->hw_addr, bptr->ar_sha, ETH_ALEN);
    d->ts = pkthdr->ts;
    *(d->dhcp_name) = '\0';
    d->vlan = ether_get_vlan(params, packet);

    buffer_advance_head(data, 1);

    return 0;
  }

  //
  // Ok if we got to here this is a normal ARP
  // Request / Reply .... few...
  //

  DEBUG_PRINT("Iface : %s Packet time : %ld ARP Source:  %-20s %-16s\n",
              params->device,
              pkthdr->ts.tv_sec,
              ether_ntoa((const struct ether_addr *)&bptr->ar_sha),
              inet_ntoa(bptr->ar_sip));

  arp_data *d = buffer_get_head(data);
  d->type = BUFFER_TYPE_ARP_SRC;
  d->ip_addr = bptr->ar_sip;
  memcpy(d->hw_addr, bptr->ar_sha, ETH_ALEN);
  d->ts = pkthdr->ts;
  *(d->dhcp_name) = '\0';
  d->vlan = ether_get_vlan(params, packet);

  buffer_advance_head(data, 1);

  //
  // If we have a ARP Reply we can capture both
  // MAC addresses
  //

  if (htons(aptr->ar_op) == ARPOP_REPLY) {
    DEBUG_PRINT("Iface : %s Packet time : %ld "
                "ARP Dest  :  %-20s %-16s\n",
                params->device,
                pkthdr->ts.tv_sec,
                ether_ntoa((const struct ether_addr *)&bptr->ar_tha),
                inet_ntoa(bptr->ar_tip));

    arp_data *d = buffer_get_head(data);
    d->type = BUFFER_TYPE_ARP_DST;
    d->ip_addr = bptr->ar_tip;
    memcpy(d->hw_addr, bptr->ar_tha, ETH_ALEN);
    d->ts = pkthdr->ts;
    *(d->dhcp_name) = '\0';
    d->vlan = ether_get_vlan(params, packet);
    buffer_advance_head(data, 1);
  }

  return 0;
}

int capture_epics_pva_packet(arpwatch_params *params,
                             const struct pcap_pkthdr* pkthdr,
                             const u_char* packet) {
#ifdef DEBUG
  (void)pkthdr;
  struct ether_header *eptr = (struct ether_header *) packet;

  unsigned int pos = ether_header_size(packet);
  struct ipbdy *iptr = (struct ipbdy *) (packet + pos);

  DEBUG_PRINT("EPICS PVA UDP Packet :  %-20s %-16s\n",
              ether_ntoa((const struct ether_addr *)&eptr->ether_shost),
              inet_ntoa(iptr->ip_sip));
#else
  (void)pkthdr;
  (void)packet;
#endif

  // Set to EPICS TYPE
  buffer_data *data = &params->data_buffer;
  arp_data *d = buffer_get_head(data);
  d->type = BUFFER_TYPE_EPICS_PVA;

  (void)params;

  return 0;
}

int capture_epics_packet(arpwatch_params *params,
                         const struct pcap_pkthdr* pkthdr,
                         const u_char* packet) {
  struct ether_header *eptr = (struct ether_header *) packet;

  unsigned int pos = ether_header_size(packet);
  struct ipbdy *iptr = (struct ipbdy *) (packet + pos);

  pos += sizeof(struct ipbdy);
  pos += sizeof(struct udphdr);
  if (pos > pkthdr->len ) return -1;

  DEBUG_PRINT("EPICS UDP Packet :  %-20s %-16s\n",
              ether_ntoa((const struct ether_addr *)&eptr->ether_shost),
              inet_ntoa(iptr->ip_sip));

  while (pos < pkthdr->len) {
    // Process messages
    struct ca_proto_msg *msg = (struct ca_proto_msg *)
                               (packet + pos);
    if (msg->command == 0) {
      DEBUG_COMMENT("Valid CA_PROTO_VERSION\n");
      pos += sizeof(struct ca_proto_msg);
    } else if (htons(msg->command) == 6) {
      DEBUG_COMMENT("Valid CA_SEARCH_REQUEST\n");
      pos += sizeof(struct ca_proto_msg);
      char name[256];
      memset(name, 0, sizeof(name));
      memcpy(name, packet + pos,
              msg->payload_size > sizeof(name) ?
              sizeof(name) : msg->payload_size);
      pos += msg->payload_size;
      DEBUG_PRINT("PV : %s\n", name);
    } else {
      break;
    }
  }

#ifndef DEBUG
  (void)iptr;
  (void)eptr;
#endif

  // Set to EPICS TYPE
  buffer_data *data = &params->data_buffer;
  arp_data *d = buffer_get_head(data);
  d->type = BUFFER_TYPE_EPICS;

  return 0;
}

int capture_dhcp_packet(arpwatch_params *params,
                        const struct pcap_pkthdr* pkthdr,
                        const u_char* packet) {
  buffer_data *data = &params->data_buffer;
  arp_data *d = buffer_get_head(data);

#ifdef DEBUG
  struct dhcpbdy *dptr = (struct dhcpbdy *)(packet
                          + ether_header_size(packet)
                          + sizeof(struct ipbdy)
                          + sizeof(struct udphdr));
  DEBUG_PRINT("DHCP OP = %d Transaction ID = 0x%0X Cookie 0x%0X\n",
              dptr->op,
              ntohl(dptr->xid),
              ntohl(dptr->cookie));
#endif

  // Set to DHCP type
  d->type = BUFFER_TYPE_DHCP_ERR;

  // Set default hostname
  strncpy(d->dhcp_name, "(none)", BUFFER_NAME_MAX);

  // Ok now we can process options.

  u_char *optr = (u_char *)(packet
                  + ether_header_size(packet)
                  + sizeof(struct ipbdy)
                  + sizeof(struct udphdr)
                  + sizeof(struct dhcpbdy));

  int pos = ether_header_size(packet)
            + sizeof(struct ipbdy)
            + sizeof(struct udphdr)
            + sizeof(struct dhcpbdy);

  while ((int)pkthdr->len > pos) {
    uint8_t code = *optr;
    optr++;
    uint8_t len = *optr;
    optr++;

    DEBUG_PRINT("DHCP OPTION %d\n", code);

    if (code == DHCP_OPCODE_END) {
      break;
    } else if (code == DHCP_OPCODE_HOSTNAME) {
      char _name[BUFFER_NAME_MAX];
      if (len < (sizeof(_name)- 1)) {
        memcpy(_name, optr, len);
        _name[len] = '\0';  // Null terminate
        strncpy(d->dhcp_name, _name, BUFFER_NAME_MAX);
        DEBUG_PRINT("DHCP Hostname : %s\n", _name);
      } else {
        ERROR_COMMENT("DHCP Name too long\n");
      }
    } else if (code == DHCP_OPCODE_MESSAGE_TYPE) {
      if (len == 1) {
        // This should be 1 byte
        int opcode = *((uint8_t*)optr);
        if ((opcode > 0) && (opcode < (int)sizeof(dhcp_message_type))) {
          DEBUG_PRINT("DHCP message type = %d\n", opcode);
          d->type = dhcp_message_type[opcode];
        } else {
          ERROR_PRINT("Error: DHCP Invalid message type %d\n", opcode);
        }
      }
    }

    optr += len;
    pos += 2 + len;
  }

  return 0;
}

int capture_ip_packet(arpwatch_params *params,
                       const struct pcap_pkthdr* pkthdr,
                       const u_char* packet) {
  struct ether_header *eptr = (struct ether_header *) packet;
  struct ipbdy *iptr = (struct ipbdy *) (packet +
                                         ether_header_size(packet));

  // Process any IP Packets that are broadcast

  DEBUG_PRINT("Iface : %s Packet time : %ld Broadcast Source:  %-20s %-16s\n",
              params->device,
              pkthdr->ts.tv_sec,
              ether_ntoa((const struct ether_addr *)&eptr->ether_shost),
              inet_ntoa(iptr->ip_sip));

  buffer_data *data = &params->data_buffer;
  arp_data *d = buffer_get_head(data);

  // Set type to UDP, we will overwrite later
  d->type = BUFFER_TYPE_IP;

  // Process IP Address
  d->ip_addr = iptr->ip_sip;

  // Set VLAN Tag
  d->vlan = ether_get_vlan(params, packet);

  // Process MAC Address
  memcpy(d->hw_addr, eptr->ether_shost, ETH_ALEN);
  d->ts = pkthdr->ts;

  // Null out the DHCP name
  *(d->dhcp_name) = '\0';

  // Further process to determine type

  if (iptr->proto == IP_PROTO_UDP) {
    // We have a UDP Packet
    struct udphdr *uptr = (struct udphdr *)(packet
                          + sizeof(struct ether_header)
                          + sizeof(struct ipbdy));

    d->type = BUFFER_TYPE_UDP;

    DEBUG_PRINT("Iface : %s %d UDP %d -> %d\n", params->device,
                sizeof(struct ipbdy),
                htons(uptr->sport), htons(uptr->dport));

    if ((htons(uptr->sport) == DHCP_DISCOVER_SPORT) &&
        (htons(uptr->dport) == DHCP_DISCOVER_DPORT)) {
      capture_dhcp_packet(params, pkthdr, packet);
    } else if (htons(uptr->dport) == EPICS_DPORT) {
      capture_epics_packet(params, pkthdr, packet);
    } else if (htons(uptr->dport) == EPICS_PVA_DPORT) {
      capture_epics_pva_packet(params, pkthdr, packet);
    }
  }

  buffer_advance_head(data, 1);

  return 0;
}

void capture_callback(u_char *args, const struct pcap_pkthdr* pkthdr,
                     const u_char* packet) {
  arpwatch_params *params = (arpwatch_params*)args;

  struct ethernet_header *eptr = (struct ethernet_header *) packet;

  uint16_t type = ntohs(eptr->ether_type);
  if (type == ETHERTYPE_8021Q) {
    // If we ignore tagged packets, just return
    if (params->ignore_tagged) {
      return;
    }

    // Tagged interface, get real type
    struct ethernet_header_8021q *_eptr =
        (struct ethernet_header_8021q *) packet;
    type = ntohs(_eptr->ether_type);
#ifdef DEBUG
    uint16_t vlan = ether_get_vlan(params, packet);
    DEBUG_PRINT("TAGGED Packet type = 0x%0X vlan = %d\n", type, vlan);
#endif
  }

  if (type == ETHERTYPE_IP) {
    capture_ip_packet(params, pkthdr, packet);
  } else if (type == ETHERTYPE_ARP) {
    capture_arp_packet(params, pkthdr, packet);
  } else {
    // Fallback to just log MAC address
    DEBUG_PRINT("Unknown packet type 0x%0X\n", type);
    capture_ethernet_packet(params, pkthdr, packet);
  }
}

int capture_start(arpwatch_params *params) {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 maskp;
  bpf_u_int32 netp;

  pcap_if_t *interfaces = NULL, *temp;

  int rtn = -1;

  if (pcap_findalldevs(&interfaces, errbuf)) {
    ERROR_COMMENT("pcap_findalldevs() : ERROR\n");
    goto _error;
  }

  if (!interfaces) {
    goto _error;
  }

  int found = 0;
  for (temp=interfaces; temp; temp=temp->next) {
    DEBUG_PRINT("Found interface : %s\n", temp->name);
    if (!strcmp(temp->name, params->device)) {
      found = 1;
      break;
    }
  }

  if (!found) {
    ERROR_PRINT("Interface %s is not valid.\n", params->device);
    goto _error;
  }

  // Get the mac address of the interface
  struct ifreq ifr;
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  strncpy(ifr.ifr_name, params->device, IFNAMSIZ);
  ioctl(s, SIOCGIFHWADDR, &ifr);
  memcpy(params->hwaddress, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  DEBUG_PRINT("MAC Address of %s : %s\n",
              params->device,
              int_to_mac(params->hwaddress));
  close(s);

  // Get the IP address and netmask of the interface
  pcap_lookupnet(params->device, &netp, &maskp, errbuf);

  pcap_description = pcap_open_live(params->device, BUFSIZ, 1,
                         params->pcap_timeout, errbuf);
  if (pcap_description == NULL) {
    ERROR_PRINT("pcap_open_live(): ERROR : %s\n", errbuf);
    goto _error;
  }

  DEBUG_PRINT("Opened interface : %s\n", params->device);

  // Compile the pcap program
  if (pcap_compile(pcap_description, &fp, params->program, 0, netp) == -1) {
    ERROR_COMMENT("pcap_compile() : ERROR\n");
    goto _error;
  }

  // Filter based on compiled program
  if (pcap_setfilter(pcap_description, &fp) == -1) {
    ERROR_COMMENT("pcap_setfilter() : ERROR\n");
    goto _error;
  }

  NOTICE_PRINT("Starting capture on : %s\n", params->device);
  pcap_loop(pcap_description, -1, capture_callback,
            (u_char*)(params));

  rtn = 0;

_error:
  if (interfaces) pcap_freealldevs(interfaces);

  return rtn;
}

int capture_stop(void) {
  if (pcap_description) {
    pcap_breakloop(pcap_description);
  }

  return 0;
}
