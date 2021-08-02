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

#include "utils.h"

char hexchars[] = { '0', '1', '2', '3', '4', '5',
                    '6', '7', '8', '9', 'A', 'B',
                    'C', 'D', 'E', 'F' };

const char * int_to_mac(unsigned char *addr) {
  static char _mac[30];
  int j = 0;
  for (int i=0; i < 6; i++) {
    _mac[j++] = hexchars[(addr[i] >> 4) & 0x0F];
    _mac[j++] = hexchars[addr[i] & 0x0F];
    _mac[j++] = ':';
  }

  _mac[j - 1] = '\0';

  return _mac;
}

int netbios_decode(char *dec, char *enc, int len) {
  char *pdec;
  char _c;
  char __c;
  int index = 0;

  pdec = enc;
  while (index < (len / 2)) {
    // NETBIOS uses 2 chars for each real char
    _c = *pdec;
    if (_c == '\0') {
      break;  // Null char
    }
    if (_c == '.') {
      break;  // Break for scope ID
    }
    if (_c < 'A' || _c > 'Z') {
      // Illegal chars
      return -1;
    }

    _c -= 'A';
    __c = _c << 4;
    pdec++;

    _c = *pdec;
    if (_c == '\0' || _c == '.') {
      // No more characters in the name - but we're in
      // the middle of a pair.  Not legal.
      return -1;
    }
    if (_c < 'A' || _c > 'Z') {
      // Not legal.
      return -1;
    }
    _c -= 'A';
    __c |= _c;
    pdec++;

    dec[index++] = (__c != ' '?__c:'\0');
  }

  return 0;
}
