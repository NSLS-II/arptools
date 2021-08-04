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

#include "buffer.h"
#include "debug.h"

int buffer_init(buffer_data *buffer, int size, int ring) {
  buffer->data = malloc(size * sizeof(arp_data));
  if (buffer->data == NULL) {
    return BUFFER_ERR_MEMORY;
  }

  /* set the initial parameters */
  buffer->head = buffer->data;
  buffer->tail = buffer->data;
  buffer->end  = buffer->data + (size - 1);
  buffer->size = size;
  buffer->ring = ring;

  buffer->full = 0;
  buffer->overruns = 0;

  /* Setup mutex */

  pthread_mutex_init(&buffer->mutex, NULL);
  pthread_cond_init(&buffer->signal, NULL);

  return BUFFER_NOERR;
}

void buffer_flush(buffer_data *buffer) {
  pthread_mutex_lock(&buffer->mutex);
  buffer->tail = buffer->head;
  buffer->full = 0;

  pthread_mutex_unlock(&buffer->mutex);
}

int buffer_overruns(buffer_data *buffer) {
  int _overruns;
  pthread_mutex_lock(&buffer->mutex);
  _overruns = buffer->overruns;
  pthread_mutex_unlock(&buffer->mutex);

  return _overruns;
}

int buffer_used_bytes(buffer_data *buffer) {
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

int buffer_used_elements(buffer_data *buffer) {
  return buffer_used_bytes(buffer) / sizeof(arp_data);
}

double buffer_percent_full(buffer_data *buffer) {
  int bytes;
  double percent;

  bytes = buffer_used_bytes(buffer);
  percent = (double)bytes / (double)(sizeof(arp_data) * buffer->size);

  return (percent * 100.0);
}

arp_data *buffer_get_head(buffer_data *buffer) {
  void *head;

  pthread_mutex_lock(&buffer->mutex);
  head = buffer->head;
  pthread_mutex_unlock(&buffer->mutex);

  return head;
}

int buffer_compare_data(arp_data *d1, arp_data *d2) {
  if ((d1->ip_addr.s_addr == d2->ip_addr.s_addr) &&
      (d1->type == d2->type) &&
      (!memcmp(d1->hw_addr, d2->hw_addr, ETH_ALEN))) {
    return 0;
  } else {
    return -1;
  }
}

void buffer_advance_head(buffer_data *buffer, int unique) {
  /* Increment the head pointet */
  pthread_mutex_lock(&buffer->mutex);

  buffer->full = 0;
  if ((buffer->head == buffer->end) && (buffer->tail == buffer->data)) {
    // We have the head at the end of the array
    // and the tail at the beginning
    buffer->full = 1;
    buffer->overruns++;
    if (!buffer->ring) {
      goto cleanup;
    }
  }

  if ((buffer->head + 1) == buffer->tail) {
    // Here the head is one ahead of the tail
    buffer->full = 1;
    buffer->overruns++;
    if (!buffer->ring) {
      goto cleanup;
    }
  }

  // We can now do verification in a loop to
  // see if we have a data match

  int match = 0;

  if ((buffer->head != buffer->tail) && unique) {
    arp_data *tmp = buffer->tail;
    do {
      if (!buffer_compare_data(tmp, buffer->head)) {
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
    // Advance both pointers
    if (buffer->head == buffer->end) {
      buffer->head = buffer->data;
    } else {
      buffer->head++;
    }

    if (buffer->ring && buffer->full) {
      if (buffer->tail == buffer->end) {
        buffer->tail = buffer->tail;
      } else {
        buffer->tail++;
      }
    }
  }

cleanup:
  pthread_cond_broadcast(&buffer->signal);
  pthread_mutex_unlock(&buffer->mutex);
}

arp_data* buffer_get_tail(buffer_data *buffer, int wait) {
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

void buffer_advance_tail(buffer_data *buffer) {
  /* Return the tail pointer and advance the BUFFER */

  pthread_mutex_lock(&buffer->mutex);

  /* If the head and tail are the same, BUFFER is empty */
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
