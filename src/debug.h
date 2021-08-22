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
#ifndef SRC_DEBUG_H_
#define SRC_DEBUG_H_

#ifdef SYSTEMD
#include <systemd/sd-daemon.h>
#else
#define SD_EMERG   ""
#define SD_ALERT   ""
#define SD_CRIT    ""
#define SD_ERR     ""
#define SD_WARNING ""
#define SD_NOTICE  ""
#define SD_INFO    ""
#define SD_DEBUG   ""
#endif

#ifndef __FILENAME__
#define __FILENAME__      __FILE__
#endif

#ifdef DEBUG

#define DEBUG_PRINT(fmt, ...) \
  fprintf(stderr, SD_DEBUG "%s:%-4d:%s(): " fmt, \
          __FILENAME__, __LINE__, __func__, __VA_ARGS__);

#define DEBUG_COMMENT(txt) \
  fprintf(stderr, SD_DEBUG "%s:%-4d:%s(): %s", \
          __FILENAME__, __LINE__, __func__, txt);

#define NOTICE_PRINT(fmt, ...) \
  fprintf(stderr, SD_NOTICE "%s:%-4d:%s(): " fmt, \
          __FILENAME__, __LINE__, __func__, __VA_ARGS__);

#define NOTICE_COMMENT(txt) \
  fprintf(stderr, SD_NOTICE "%s:%-4d:%s(): %s", \
          __FILENAME__, __LINE__, __func__, txt);

#define ERROR_PRINT(fmt, ...) \
  fprintf(stderr, SD_ERR "%s:%-4d:%s(): " fmt, \
          __FILENAME__, __LINE__, __func__, __VA_ARGS__);

#define ERROR_COMMENT(txt) \
  fprintf(stderr, SD_ERR "%s:%-4d:%s(): %s", \
          __FILENAME__, __LINE__, __func__, txt);

#define ALERT_PRINT(fmt, ...) \
  fprintf(stderr, SD_ALERT "%s:%-4d:%s(): " fmt, \
          __FILENAME__, __LINE__, __func__, __VA_ARGS__);

#define ALERT_COMMENT(txt) \
  fprintf(stderr, SD_ALERT "%s:%-4d:%s(): %s", \
          __FILENAME__, __LINE__, __func__, txt);

#else

#define DEBUG_PRINT(fmt, ...) \
  do {} while (0)

#define DEBUG_COMMENT(txt) \
  do {} while (0)

#define NOTICE_PRINT(fmt, ...) \
  fprintf(stderr, SD_NOTICE fmt, \
          __VA_ARGS__);

#define NOTICE_COMMENT(txt) \
  fprintf(stderr, SD_NOTICE "%s", txt);

#define ERROR_PRINT(fmt, ...) \
  fprintf(stderr, SD_ERR "%s(): " fmt, \
          __func__, __VA_ARGS__);

#define ERROR_COMMENT(txt) \
  fprintf(stderr, SD_ERR "%s(): %s", \
          __func__, txt);

#define ALERT_PRINT(fmt, ...) \
  fprintf(stderr, SD_ERR "%s(): " fmt, \
          __func__, __VA_ARGS__);

#define ALERT_COMMENT(txt) \
  fprintf(stderr, SD_ALERT "%s", txt);

#endif

#endif  // SRC_DEBUG_H_
