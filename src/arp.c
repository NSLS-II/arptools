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

#include <libnet.h>
#include "debug.h"
#include "utils.h"
#include "arp.h"
#include "arpwatch.h"

uint8_t hw_bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int arp_send(arpwatch_params *params) {
  struct libnet_ether_addr* hw_addr = NULL;
  libnet_t *l;
  char errbuf[LIBNET_ERRBUF_SIZE];

  int rtn = -1;

  if ((l = libnet_init(LIBNET_LINK_ADV,
                       params->device,
                       errbuf)) == NULL) {
    ERROR_COMMENT("Unable to initialize libnet\n");
    return -1;
  }

  // Get hardware (MAC) address

  if ((hw_addr = libnet_get_hwaddr(l)) == NULL) {
    ERROR_COMMENT("Unable to read HW address.\n");
    goto _error;
  }

  DEBUG_PRINT("Interface HW Address %s\n",
              int_to_mac((unsigned char*)hw_addr));

  // Get link type

  u_short hrd;
  switch (l->link_type) {
    case 1: /* DLT_EN10MB */
      hrd = ARPHRD_ETHER;
      DEBUG_COMMENT("Link type ETHER\n");
      break;
    case 6: /* DLT_IEEE802 */
      DEBUG_COMMENT("Link type IEEE802\n");
      hrd = ARPHRD_IEEE802;
      break;
    default:
      DEBUG_COMMENT("Unsupported link type\n");
      goto _error;
  }

  // Now loop over possible networks

  for (int net = 0; net < params->num_network; net++) {
    uint32_t ip_addr;
    libnet_ptag_t arpt = 0;
    libnet_ptag_t ethert = 0;

    // Clear the packet info (just incase we change from
    // Tagged to Untagged

    libnet_clear_packet(l);

    // Set the IP Address from either
    // interface or config file

    if (!params->network[net].ipaddress_source) {
      ip_addr = libnet_get_ipaddr4(l);
      DEBUG_COMMENT("Using interface IP address\n");
    } else {
      ip_addr = params->network[net].ipaddress_source;
      DEBUG_COMMENT("Using ipaddress_source for IP address\n");
    }
    // Now calculate subnet mask
    uint32_t _subnet = ntohl(params->network[net].subnet);
    uint32_t _ip_probe = ntohl(params->network[net].ipaddress);

#ifdef DEBUG
    if (params->network[net].vlan) {
      DEBUG_PRINT("VLAN : %d PRI : %d DEI : %d\n",
                  params->network[net].vlan,
                  params->network[net].vlan_pri,
                  params->network[net].vlan_dei);
    }
#endif

    // Loop over all addresses in subnet
    for (uint32_t hostid=1; hostid < (~_subnet); hostid++) {
      uint32_t ip = htonl(_ip_probe + hostid);

#ifdef DEBUG
      struct in_addr _ip;
      _ip.s_addr = ip;
      DEBUG_PRINT("Probing : %s\n", inet_ntoa(_ip));
#endif

      if ((arpt = libnet_build_arp(hrd, ETHERTYPE_IP, 6, 4,
                                  ARPOP_REQUEST,
                                  (uint8_t*)hw_addr,
                                  (uint8_t*)&ip_addr,
                                  hw_bcast, (uint8_t*)(&ip),
                                  NULL, 0, l, arpt)) == -1) {
        ERROR_PRINT("Can't build ARP header: %s\n", libnet_geterror(l));
        goto _error;
      }

      if (ethert == 0) {
        if (params->network[net].vlan) {
          if ((ethert = libnet_build_802_1q(hw_bcast, (uint8_t*)hw_addr,
                                            ETHERTYPE_VLAN,    /* TPI */
                                            params->network[net].vlan_pri,
                                            params->network[net].vlan_dei,
                                            params->network[net].vlan,
                                            ETHERTYPE_ARP, NULL, 0, l,
                                            ethert)) == -1) {
            ERROR_PRINT("Can't build 802.1q header: %s\n", libnet_geterror(l));
            goto _error;
          }
        } else {
          if ((ethert = libnet_build_ethernet(hw_bcast, (uint8_t*)hw_addr,
                                              ETHERTYPE_ARP, NULL, 0, l,
                                              ethert)) == -1) {
            ERROR_PRINT("Can't build ethernet header: %s\n",
                        libnet_geterror(l));
            goto _error;
          }
        }
      }

      if (libnet_write(l) == -1) {
        ERROR_PRINT("Write error: %s\n", libnet_geterror(l));
        goto _error;
      }

      // Now sleep
      if (params->arp_delay != 0) {
        usleep(params->arp_delay);
      }
    }  // Single subnet
  }  // All subnets

  rtn = 0;

_error:
    libnet_destroy(l);
    return rtn;
}

void* arp_thread(void *ctx) {
  arpwatch_params *params = (arpwatch_params*)ctx;

  for (;;) {
    for (int i = 0; i < params->num_network; i++) {
      arp_send(params);
    }

    DEBUG_PRINT("Waiting for %ds\n", params->arp_loop_delay);
    sleep(params->arp_loop_delay);
  }
  return NULL;
}

int arp_setup(arpwatch_params *params) {
  pthread_t threadId;
  int err = pthread_create(&threadId, NULL,
                           &arp_thread, (void *)params);
  if (err) {
    ERROR_COMMENT("Unable to create thread.");
    return -1;
  }
  return 0;
}
