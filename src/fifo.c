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

int fifo_init(fifo *f, int size) {
  f->data = malloc(size * sizeof(arp_data));
  if (f->data == NULL) {
    return FIFO_ERR_MEMORY;
  }

  /* set the initial parameters */
  f->head = f->data;
  f->tail = f->data;
  f->end  = f->data + (size - 1);
  f->size = size;

  f->full = 0;
  f->overruns = 0;

  /* Setup mutex */

  pthread_mutex_init(&f->mutex, NULL);
  pthread_cond_init(&f->signal, NULL);

  return FIFO_NOERR;
}

void fifo_flush(fifo *f) {
  pthread_mutex_lock(&f->mutex);
  f->tail = f->head;
  f->full = 0;

  pthread_mutex_unlock(&f->mutex);
}

int fifo_overruns(fifo *f) {
  int _overruns;
  pthread_mutex_lock(&f->mutex);
  _overruns = f->overruns;
  pthread_mutex_unlock(&f->mutex);

  return _overruns;
}

int fifo_used_bytes(fifo *f) {
  int bytes = 0;
  int used;

  pthread_mutex_lock(&f->mutex);

  if (f->head >= f->tail) {
    used = (int)(f->head - f->tail);
  } else {
    used = (int)((f->end - f->tail) + (f->head - f->data));
  }

  if (used > bytes) {
    bytes = used;
  }

  pthread_mutex_unlock(&f->mutex);
  return bytes;
}

int fifo_used_elements(fifo *f) {
  return fifo_used_bytes(f) / sizeof(arp_data);
}

double fifo_percent_full(fifo *f) {
  int bytes;
  double percent;

  bytes = fifo_used_bytes(f);
  percent = (double)bytes / (double)(sizeof(arp_data) * f->size);

  return (percent * 100.0);
}

arp_data *fifo_get_head(fifo *f) {
  void *head;

  pthread_mutex_lock(&f->mutex);
  head = f->head;
  pthread_mutex_unlock(&f->mutex);

  return head;
}

void fifo_advance_head(fifo *f) {
  /* Increment the head pointet */
  pthread_mutex_lock(&f->mutex);

  /* Check all the tail pointers */

  if ((f->head == f->end) && (f->tail == f->data)) {
    f->full = 1;
    f->overruns++;
    goto cleanup;
  } else if ((f->head + 1) == f->tail) {
    f->full = 1;
    f->overruns++;
    goto cleanup;
  }

  if (f->head == f->end) {
    f->head = f->data;
    f->full = 0;
  } else {
    f->head++;
    f->full = 0;
  }

cleanup:
  pthread_cond_broadcast(&f->signal);
  pthread_mutex_unlock(&f->mutex);
}

arp_data* fifo_get_tail(fifo *f, int wait) {
  void* tail;

  pthread_mutex_lock(&f->mutex);

  if (f->tail == f->head) {
    if (wait) {
      while (f->tail == f->head) {
        pthread_cond_wait(&f->signal, &f->mutex);
      }

      tail = f->tail;
    } else {
      tail = NULL;
    }
  } else {
    tail = f->tail;
  }

  pthread_mutex_unlock(&f->mutex);

  return tail;
}

void fifo_advance_tail(fifo *f) {
  /* Return the tail pointer and advance the FIFO */

  pthread_mutex_lock(&f->mutex);

  /* If the head and tail are the same, FIFO is empty */
  if (f->tail == f->head) {
    return;
  }

  if (f->tail == f->end) {
    f->tail = f->data;
  } else {
    f->tail++;
  }

  pthread_mutex_unlock(&f->mutex);
}
