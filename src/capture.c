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

int capture_ethernet_packet(arpwatch_params *params,
                            const struct pcap_pkthdr* pkthdr,
                            const u_char* packet) {
  struct ether_header *eptr = (struct ether_header *) packet;
  uint16_t type = ntohs(eptr->ether_type);

  ERROR_PRINT("ETHERNET Packet type %d (0x%0X) from %s\n",
              type, type,
              ether_ntoa((const struct ether_addr *)&eptr->ether_shost));

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

  buffer_advance_head(data, 1);

  return 0;
}

int capture_arp_packet(arpwatch_params *params,
                       const struct pcap_pkthdr* pkthdr,
                       const u_char* packet) {
  struct arphdr *aptr = (struct arphdr *)(packet +
                         sizeof(struct ether_header));
  struct arpbdy *bptr;

  if (ntohs(aptr->ar_pro) != 0x0800) {
    ERROR_PRINT("%s: Bad ARP Packet (not IPV4)\n", params->iface);
    return -1;
  }

  if (ntohs(aptr->ar_hrd) != ARPHRD_ETHER) {
    ERROR_PRINT("%s: Bad ARP Packet (not ETHER)\n", params->iface);
    return -1;
  }

  if (aptr->ar_hln != ETH_ALEN) {
    ERROR_PRINT("%s: Bad ARP Packet (Invalid Hardware Address)\n",
                params->iface);
    return -1;
  }

  if (aptr->ar_pln != sizeof(struct in_addr)) {
    ERROR_PRINT("%s: Bad ARP Packet (Invalid IP Address)\n",
                params->iface);
    return -1;
  }

  buffer_data *data = &params->data_buffer;

  if ((htons(aptr->ar_op) == ARPOP_REPLY) ||
      (htons(aptr->ar_op) == ARPOP_REQUEST)) {
    bptr = (struct arpbdy *) (packet +
      sizeof(struct ether_header) + sizeof(struct arphdr));

    if (memcmp(params->hwaddress, bptr->ar_sha, ETH_ALEN) ||
        !params->filter_self) {
      DEBUG_PRINT("Iface : %s Packet time : %ld ARP Source:  %-20s %-16s\n",
                  params->iface,
                  pkthdr->ts.tv_sec,
                  ether_ntoa((const struct ether_addr *)&bptr->ar_sha),
                  inet_ntoa(bptr->ar_sip));

      arp_data *d = buffer_get_head(data);
      d->type = BUFFER_TYPE_ARP_SRC;
      d->ip_addr = bptr->ar_sip;
      memcpy(d->hw_addr, bptr->ar_sha, ETH_ALEN);
      d->ts = pkthdr->ts;
      *(d->dhcp_name) = '\0';
      buffer_advance_head(data, 1);

      if (htons(aptr->ar_op) == ARPOP_REPLY) {
        DEBUG_PRINT("Iface : %s Packet time : %ld ARP Dest  :  %-20s %-16s\n",
                    params->iface,
                    pkthdr->ts.tv_sec,
                    ether_ntoa((const struct ether_addr *)&bptr->ar_tha),
                    inet_ntoa(bptr->ar_tip));

        arp_data *d = buffer_get_head(data);
        d->type = BUFFER_TYPE_ARP_DST;
        d->ip_addr = bptr->ar_tip;
        memcpy(d->hw_addr, bptr->ar_tha, ETH_ALEN);
        d->ts = pkthdr->ts;
        *(d->dhcp_name) = '\0';
        buffer_advance_head(data, 1);
      }
    } else {
      DEBUG_COMMENT("Skipping packet ... MAC matches host\n");
    }
  }

  return 0;
}

int capture_dhcp_packet(arpwatch_params *params,
                        const struct pcap_pkthdr* pkthdr,
                        const u_char* packet) {
  buffer_data *data = &params->data_buffer;
  arp_data *d = buffer_get_head(data);

#ifdef DEBUG
  struct dhcpbdy *dptr = (struct dhcpbdy *)(packet
                          + sizeof(struct ether_header)
                          + sizeof(struct ipbdy)
                          + sizeof(struct udphdr));
  DEBUG_PRINT("DHCP OP = %d Transaction ID = 0x%0X Cookie 0x%0X\n",
              dptr->op,
              ntohl(dptr->xid),
              ntohl(dptr->cookie));
#endif

  // Set to DHCP type
  d->type = BUFFER_TYPE_DHCP;

  // Set default hostname
  strncpy(d->dhcp_name, "(none)", BUFFER_NAME_MAX);

  // Ok now we can process options.

  u_char *optr = (u_char *)(packet
                  + sizeof(struct ether_header)
                  + sizeof(struct ipbdy)
                  + sizeof(struct udphdr)
                  + sizeof(struct dhcpbdy));

  int pos = sizeof(struct ether_header)
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
  struct ipbdy *iptr = (struct ipbdy *) (packet + sizeof(struct ether_header));

  // Process any IP Packets that are broadcast

  DEBUG_PRINT("Iface : %s Packet time : %ld Broadcast Source:  %-20s %-16s\n",
              params->iface,
              pkthdr->ts.tv_sec,
              ether_ntoa((const struct ether_addr *)&eptr->ether_shost),
              inet_ntoa(iptr->ip_sip));

  buffer_data *data = &params->data_buffer;
  arp_data *d = buffer_get_head(data);

  // Set type to UDP, we will overwrite later
  d->type = BUFFER_TYPE_IP;

  // Process IP Address
  d->ip_addr = iptr->ip_sip;

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

    DEBUG_PRINT("Iface : %s %d UDP %d -> %d\n", params->iface,
                sizeof(struct ipbdy),
                htons(uptr->sport), htons(uptr->dport));

    if ((htons(uptr->sport) == DHCP_DISCOVER_SPORT) &&
        (htons(uptr->dport) == DHCP_DISCOVER_DPORT)) {
      capture_dhcp_packet(params, pkthdr, packet);
    }
  }

  buffer_advance_head(data, 1);

  return 0;
}

void capture_callback(u_char *args, const struct pcap_pkthdr* pkthdr,
                     const u_char* packet) {
  arpwatch_params *params = (arpwatch_params*)args;

  struct ether_header *eptr = (struct ether_header *) packet;
  uint16_t type = ntohs(eptr->ether_type);

  if (type == ETHERTYPE_IP) {
    capture_ip_packet(params, pkthdr, packet);
  } else if (type == ETHERTYPE_ARP) {
    capture_arp_packet(params, pkthdr, packet);
  } else {
    // Fallback to just log MAC address
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
    if (!strcmp(temp->name, params->iface)) {
      found = 1;
      break;
    }
  }

  if (!found) {
    ERROR_PRINT("Interface %s is not valid.\n", params->iface);
    goto _error;
  }

  // Get the mac address of the interface
  struct ifreq ifr;
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  strncpy(ifr.ifr_name, params->iface, IFNAMSIZ);
  ioctl(s, SIOCGIFHWADDR, &ifr);
  memcpy(params->hwaddress, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  DEBUG_PRINT("MAC Address of %s : %s\n",
              params->iface,
              int_to_mac(params->hwaddress));
  close(s);

  // Get the IP address and netmask of the interface
  pcap_lookupnet(params->iface, &netp, &maskp, errbuf);

  pcap_description = pcap_open_live(params->iface, BUFSIZ, 1,
                         params->pcap_timeout, errbuf);
  if (pcap_description == NULL) {
    ERROR_PRINT("pcap_open_live(): ERROR : %s\n", errbuf);
    goto _error;
  }

  DEBUG_PRINT("Opened interface : %s\n", params->iface);

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

  NOTICE_PRINT("Starting capture on : %s\n", params->iface);
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
