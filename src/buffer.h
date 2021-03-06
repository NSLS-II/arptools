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

#ifndef SRC_BUFFER_H_
#define SRC_BUFFER_H_

#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

/* Macro Definitions */

#define BUFFER_ERR_MEMORY        1
#define BUFFER_NOERR             0
#define BUFFER_NAME_MAX          256
#define BUFFER_PV_MAX            32
#define BUFFER_PV_NAME_MAX       50

#define BUFFER_TYPE_UNKNOWN           0x00000000
#define BUFFER_TYPE_ARP_SRC           0x00000001
#define BUFFER_TYPE_ARP_DST           0x00000002
#define BUFFER_TYPE_ARP_PROBE         0x00000004
#define BUFFER_TYPE_ARP_GRAT          0x00000008
#define BUFFER_TYPE_UDP               0x00000010
#define BUFFER_TYPE_DHCP_ERR          0x00000020
#define BUFFER_TYPE_IP                0x00000040
#define BUFFER_TYPE_EPICS             0x00000080
#define BUFFER_TYPE_EPICS_PVA         0x00000100
#define BUFFER_TYPE_DHCP_DISCOVER     0x00000200
#define BUFFER_TYPE_DHCP_OFFER        0x00000400
#define BUFFER_TYPE_DHCP_REQUEST      0x00000800
#define BUFFER_TYPE_DHCP_DECLINE      0x00001000
#define BUFFER_TYPE_DHCP_ACK          0x00002000
#define BUFFER_TYPE_DHCP_NACK         0x00004000
#define BUFFER_TYPE_DHCP_RELEASE      0x00008000
#define BUFFER_TYPE_EPICS_BEACON      0x00010000

#define BUFFER_TYPE_ARP               (BUFFER_TYPE_ARP_SRC      | \
                                       BUFFER_TYPE_ARP_DST      | \
                                       BUFFER_TYPE_ARP_PROBE    | \
                                       BUFFER_TYPE_ARP_GRAT)

#define BUFFER_TYPE_DHCP              (BUFFER_TYPE_DHCP_DISCOVER  | \
                                       BUFFER_TYPE_DHCP_OFFER     | \
                                       BUFFER_TYPE_DHCP_REQUEST   | \
                                       BUFFER_TYPE_DHCP_DECLINE   | \
                                       BUFFER_TYPE_DHCP_ACK       | \
                                       BUFFER_TYPE_DHCP_NACK      | \
                                       BUFFER_TYPE_DHCP_RELEASE)

typedef struct {
  unsigned char hw_addr[ETH_ALEN];
  struct in_addr ip_addr;
  struct timeval ts;
  int type;
  uint16_t vlan;
  char dhcp_name[BUFFER_NAME_MAX];
  char pv_name[BUFFER_PV_MAX][BUFFER_PV_NAME_MAX];
  int pv_num;
} arp_data;

typedef struct {
  arp_data *data;
  arp_data *head;
  arp_data *tail;
  arp_data *end;
  int size;
  int full;
  int overruns;
  int ring;
  pthread_mutex_t mutex;
  pthread_cond_t signal;
} buffer_data;


/* BUFFER Functions */

arp_data* buffer_get_head(buffer_data *buffer);
/*
 * Return the head of the BUFFER element pointed to by f.
 * This routine will signal that new data is avaliable in
 * the buffer using "pthread_cond_signal"
 */
arp_data* buffer_get_tail(buffer_data *buffer, int wait);
/*
 * Return the tail of the BUFFER element pointed to by f.
 * This routine will block until data is avaliable, waiting
 * on the signal sent by "buffer_get_head". If data is on the
 * buffer then it will immediately return
 */
void buffer_advance_head(buffer_data *buffer, int unique);
/*
 * Advance the head pointer, signalling we are done filling
 * the buffer with an element.
 */
void buffer_advance_tail(buffer_data *buffer);
/*
 * Advance the tail pointer, signalling we have processed a buffer
 * element and this can be returned
 */
int buffer_init(buffer_data *buffer, int size, int ring);
/*
 * Initialize the buffer. The BUFFER is of length size with a data
 * structure of length elem_size.
 */
void buffer_free(buffer_data *buffer);
int buffer_used_bytes(buffer_data *buffer);
double buffer_percent_full(buffer_data *buffer);
int buffer_used_elements(buffer_data *buffer);
void buffer_flush(buffer_data *buffer);
int buffer_overruns(buffer_data *buffer);

#endif  // SRC_BUFFER_H_
