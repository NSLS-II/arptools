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

#ifndef SRC_FIFO_H_
#define SRC_FIFO_H_

#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

/* Macro Definitions */

#define FIFO_ERR_MEMORY        1
#define FIFO_NOERR             0
#define FIFO_NAME_MAX          256
#define FIFO_TYPE_ARP_SRC      0x00
#define FIFO_TYPE_ARP_DST      0x01
#define FIFO_TYPE_UDP          0x02
#define FIFO_TYPE_DHCP         0x04
#define FIFO_TYPE_UNKNOWN      0x08

typedef struct {
  unsigned char hw_addr[ETH_ALEN];
  struct in_addr ip_addr;
  struct timeval ts;
  int type;
  char dhcp_name[FIFO_NAME_MAX];
} arp_data;

typedef struct {
  arp_data *data;
  arp_data *head;
  arp_data *tail;
  arp_data *end;
  int size;
  int full;
  int overruns;
  pthread_mutex_t mutex;
  pthread_cond_t signal;
} fifo;


#ifdef __cplusplus
extern "C" {
#endif

/* FIFO Functions */

arp_data* fifo_get_head(fifo *f);
/*
 * Return the head of the FIFO element pointed to by f.
 * This routine will signal that new data is avaliable in
 * the fifo using "pthread_cond_signal"
 */
arp_data* fifo_get_tail(fifo *f, int wait);
/*
 * Return the tail of the FIFO element pointed to by f.
 * This routine will block until data is avaliable, waiting
 * on the signal sent by "fifo_get_head". If data is on the
 * fifo then it will immediately return
 */
void fifo_advance_head(fifo *f);
/*
 * Advance the head pointer, signalling we are done filling
 * the fifo with an element.
 */
void fifo_advance_tail(fifo *f);
/*
 * Advance the tail pointer, signalling we have processed a fifo
 * element and this can be returned
 */
int fifo_init(fifo *f, int size);
/*
 * Initialize the fifo. The FIFO is of length size with a data
 * structure of length elem_size.
 */
int fifo_used_bytes(fifo *f);
double fifo_percent_full(fifo *f);
int fifo_used_elements(fifo *f);
void fifo_flush(fifo *f);
int fifo_overruns(fifo *f);
#ifdef __cplusplus
}
#endif

#endif  // SRC_FIFO_H_
