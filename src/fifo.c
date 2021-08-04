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

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "fifo.h"
#include "debug.h"

int fifo_init(fifo *buffer, int size) {
  buffer->data = malloc(size * sizeof(arp_data));
  if (buffer->data == NULL) {
    return FIFO_ERR_MEMORY;
  }

  /* set the initial parameters */
  buffer->head = buffer->data;
  buffer->tail = buffer->data;
  buffer->end  = buffer->data + (size - 1);
  buffer->size = size;

  buffer->full = 0;
  buffer->overruns = 0;

  /* Setup mutex */

  pthread_mutex_init(&buffer->mutex, NULL);
  pthread_cond_init(&buffer->signal, NULL);

  return FIFO_NOERR;
}

void fifo_flush(fifo *buffer) {
  pthread_mutex_lock(&buffer->mutex);
  buffer->tail = buffer->head;
  buffer->full = 0;

  pthread_mutex_unlock(&buffer->mutex);
}

int fifo_overruns(fifo *buffer) {
  int _overruns;
  pthread_mutex_lock(&buffer->mutex);
  _overruns = buffer->overruns;
  pthread_mutex_unlock(&buffer->mutex);

  return _overruns;
}

int fifo_used_bytes(fifo *buffer) {
  int bytes = 0;
  int used;

  pthread_mutex_lock(&buffer->mutex);

  if (buffer->head >= buffer->tail) {
    used = (int)(buffer->head - buffer->tail);
  } else {
    used = (int)((buffer->end - buffer->tail) + (buffer->head - buffer->data));
  }

  if (used > bytes) {
    bytes = used;
  }

  pthread_mutex_unlock(&buffer->mutex);
  return bytes;
}

int fifo_used_elements(fifo *buffer) {
  return fifo_used_bytes(buffer) / sizeof(arp_data);
}

double fifo_percent_full(fifo *buffer) {
  int bytes;
  double percent;

  bytes = fifo_used_bytes(buffer);
  percent = (double)bytes / (double)(sizeof(arp_data) * buffer->size);

  return (percent * 100.0);
}

arp_data *fifo_get_head(fifo *buffer) {
  void *head;

  pthread_mutex_lock(&buffer->mutex);
  head = buffer->head;
  pthread_mutex_unlock(&buffer->mutex);

  return head;
}

void fifo_advance_head(fifo *buffer, int unique) {
  /* Increment the head pointet */
  pthread_mutex_lock(&buffer->mutex);

  /* Check all the tail pointers */

  if ((buffer->head == buffer->end) && (buffer->tail == buffer->data)) {
    buffer->full = 1;
    buffer->overruns++;
    goto cleanup;
  } else if ((buffer->head + 1) == buffer->tail) {
    buffer->full = 1;
    buffer->overruns++;
    goto cleanup;
  }

  // We can now do verification in a loop to
  // see if we have a data match

  int match = 0;

  if ((buffer->head != buffer->tail) && unique) {
    arp_data *tmp = buffer->tail;
    do {
      if ((tmp->ip_addr.s_addr == buffer->head->ip_addr.s_addr) &&
          (tmp->type == buffer->head->type) &&
          (!memcmp(tmp->hw_addr, buffer->head->hw_addr, ETH_ALEN))) {
          // Data matches
          DEBUG_PRINT("Skipping, data exists %p\n", tmp);
          match = -1;
          break;
      }

      // Advance the tmp pointer
      if (tmp == buffer->end) {
        tmp = buffer->data;
      } else {
        tmp++;
      }
    } while (tmp != buffer->head);
  }

  if (!match) {
    if (buffer->head == buffer->end) {
      buffer->head = buffer->data;
      buffer->full = 0;
    } else {
      buffer->head++;
      buffer->full = 0;
    }
  }

cleanup:
  pthread_cond_broadcast(&buffer->signal);
  pthread_mutex_unlock(&buffer->mutex);
}

arp_data* fifo_get_tail(fifo *buffer, int wait) {
  void* tail;

  pthread_mutex_lock(&buffer->mutex);

  if (buffer->tail == buffer->head) {
    if (wait) {
      while (buffer->tail == buffer->head) {
        pthread_cond_wait(&buffer->signal, &buffer->mutex);
      }

      tail = buffer->tail;
    } else {
      tail = NULL;
    }
  } else {
    tail = buffer->tail;
  }

  pthread_mutex_unlock(&buffer->mutex);

  return tail;
}

void fifo_advance_tail(fifo *buffer) {
  /* Return the tail pointer and advance the FIFO */

  pthread_mutex_lock(&buffer->mutex);

  /* If the head and tail are the same, FIFO is empty */
  if (buffer->tail == buffer->head) {
    return;
  }

  if (buffer->tail == buffer->end) {
    buffer->tail = buffer->data;
  } else {
    buffer->tail++;
  }

  pthread_mutex_unlock(&buffer->mutex);
}
