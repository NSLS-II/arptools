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

#include "fifo.h"
#include "debug.h"
#include "arpwatch.h"
#include "capture.h"
#include "utils.h"

pcap_t *pcap_description = NULL;

void capture_callback(u_char *args, const struct pcap_pkthdr* pkthdr,
                     const u_char* packet) {
  struct ether_header *eptr;
  struct arphdr *aptr;
  struct arpbdy *bptr;

  arpwatch_params *params = (arpwatch_params*)args;
  fifo *data = &params->data_fifo;

  eptr = (struct ether_header *) packet;

  // Check for ARP Packets

  if (ntohs(eptr->ether_type) != ETHERTYPE_ARP) {
    return;
  }

  aptr = (struct arphdr *) (packet + sizeof(struct ether_header));

  if (ntohs(aptr->ar_pro) != 0x0800) {  // IPV4
    return;
  }

  if (ntohs(aptr->ar_hrd) != ARPHRD_ETHER) {  // IPV4
    return;
  }

  if (aptr->ar_hln != ETH_ALEN) {
    return;
  }

  if (aptr->ar_pln != sizeof(struct in_addr)) {
    return;
  }

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

      arp_data *d = fifo_get_head(data);
      d->ip_addr = bptr->ar_sip;
      memcpy(d->hw_addr, bptr->ar_sha, ETH_ALEN);
      d->ts = pkthdr->ts;
      fifo_advance_head(data);

      if (htons(aptr->ar_op) == ARPOP_REPLY) {
        DEBUG_PRINT("Iface : %s Packet time : %ld ARP Dest  :  %-20s %-16s\n",
                    params->iface,
                    pkthdr->ts.tv_sec,
                    ether_ntoa((const struct ether_addr *)&bptr->ar_tha),
                    inet_ntoa(bptr->ar_tip));

        arp_data *d = fifo_get_head(data);
        d->ip_addr = bptr->ar_tip;
        memcpy(d->hw_addr, bptr->ar_tha, ETH_ALEN);
        d->ts = pkthdr->ts;
        fifo_advance_head(data);
      }
    } else {
      DEBUG_COMMENT("Skipping packet ... MAC matches host\n");
    }
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
