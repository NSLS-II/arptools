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

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>

#include "debug.h"
#include "buffer.h"
#include "mysql.h"
#include "utils.h"
#include "arpwatch.h"

unsigned int mysql_handle_error(MYSQL *con) {
  const char *err = mysql_error(con);
  unsigned int errno = mysql_errno(con);

  if (errno) {
    // We have a valid SQL Error string
    ERROR_PRINT("MySQL Error : %s\n", err);
  }

  return errno;
}

void * mysql_thread(void * arg) {
  arpwatch_params *params = (arpwatch_params *) arg;

  NOTICE_COMMENT("Starting mysql thread\n");

  for (;;) {
    char sql_buffer[100000];
    MYSQL *con = mysql_init(NULL);
    if (!con) {
      mysql_handle_error(con);
      goto _error;
    }

    if (mysql_real_connect(con, params->hostname,
                           params->username,
                           params->password,
                           params->database,
                           0, NULL, 0) == NULL) {
      mysql_handle_error(con);
      goto _error;
    }

    // Write to daemon database

    snprintf(sql_buffer, sizeof(sql_buffer),
            "INSERT INTO daemondata "
            "(hostname, iface, last_updated) "
            "VALUES ('%s','%s',NOW()) "
            "ON DUPLICATE KEY UPDATE "
            "last_updated = NOW();",
            params->daemon_hostname,
            params->device);

    DEBUG_PRINT("DAEMON SQL query : %s\n", sql_buffer);

    if (mysql_real_query(con, sql_buffer, strlen(sql_buffer))) {
      mysql_handle_error(con);
    }

    arp_data *arp = buffer_get_tail(&(params->data_buffer), 0);

    while (arp) {
      char time_buffer[256];
      char hostname[256];

      struct tm gm;
      if (localtime_r(&(arp->ts.tv_sec), &gm)) {
        strftime(time_buffer, sizeof(time_buffer),
                "%Y-%m-%d %H:%M:%S", &gm);

        DEBUG_PRINT("Packet time : %s\n", time_buffer);
      } else {
        // Error building time
        strncpy(time_buffer, "1970-01-01 00:00:00", sizeof(time_buffer));
        ERROR_COMMENT("Unable to convert packet time");
      }

      // Now lookup DNS entry
      // TODO(swilkins) : Use reentrant version here

      struct  hostent *he = gethostbyaddr(&arp->ip_addr,
                                          sizeof(arp->ip_addr),
                                          AF_INET);
      if (he) {
        snprintf(hostname, sizeof(hostname), "'%s'", he->h_name);
        DEBUG_PRINT("Hostname : %s\n", hostname);
      } else {
        snprintf(hostname, sizeof(hostname), "NULL");
        DEBUG_PRINT("Hostname (not found) : %s\n", hostname);
      }

      const char *hw_addr = int_to_mac(arp->hw_addr);
      const char *ip_addr = inet_ntoa(arp->ip_addr);
      //
      // Database:
      // Currently KEY fields are (hw_address, vlan, location)
      // This allows for duplicate MACs as long as they are
      // Unique to VLAN and location
      //
      // First lets insert the common data of
      // hw_address
      // ip_address
      // location
      // label
      // type
      // last_seen
      // hostname
      // vlan
      //
      snprintf(sql_buffer, sizeof(sql_buffer),
              "INSERT INTO arpdata "
              "(hw_address, vlan, location, "
              "label, ip_address, type, last_seen, hostname) "
              "VALUES ('%s',%d,'%s',"
              "'%s','%s', %d, '%s', %s) "
              "ON DUPLICATE KEY UPDATE "
              "ip_address = '%s', "
              "label = '%s', "
              "type = type | %d, "
              "last_seen = '%s', "
              "hostname = %s",
              hw_addr, arp->vlan, params->location,  // KEY FIELDS
              params->label, ip_addr, arp->type, time_buffer, hostname,
              ip_addr, params->label, arp->type, time_buffer, hostname);

      DEBUG_PRINT("BASE SQL query : %s\n", sql_buffer);

      if (mysql_real_query(con, sql_buffer, strlen(sql_buffer))) {
        if (mysql_handle_error(con) == ER_DUP_ENTRY) {
          ALERT_PRINT("Duplicate database entry found for %s %d %s\n",
                      hw_addr, arp->vlan, params->location);
        }
      }

      if ((arp->type & BUFFER_TYPE_DHCP) && (*arp->dhcp_name)) {
        snprintf(sql_buffer, sizeof(sql_buffer),
                "UPDATE arpdata SET "
                "dhcp_name = '%s' "
                "WHERE hw_address = '%s' "
                "AND vlan = %d AND location = '%s';",
                arp->dhcp_name, hw_addr, arp->vlan,
                params->location);

        DEBUG_PRINT("DHCP SQL query : %s\n", sql_buffer);

        if (mysql_real_query(con, sql_buffer, strlen(sql_buffer))) {
          mysql_handle_error(con);
        }
      }

      if (arp->type & BUFFER_TYPE_EPICS) {
        for (int pvc=0; pvc < arp->pv_num; pvc++) {
          snprintf(sql_buffer, sizeof(sql_buffer),
                  "INSERT INTO epicsdata "
                  "(hw_address, vlan, pv_name, last_seen) "
                  "VALUES ('%s', %d, '%s', '%s') "
                  "ON DUPLICATE KEY UPDATE "
                  "last_seen = '%s';",
                  hw_addr, arp->vlan, arp->pv_name[pvc],
                  time_buffer, time_buffer);

          DEBUG_PRINT("EPICSDATA SQL query : %s\n", sql_buffer);

          if (mysql_real_query(con, sql_buffer, strlen(sql_buffer))) {
            mysql_handle_error(con);
          }
        }
      }

      buffer_advance_tail(&(params->data_buffer));
      arp = buffer_get_tail(&(params->data_buffer), 0);
    }

_error:
    if (con) mysql_close(con);
    DEBUG_PRINT("Sleep for %d\n", params->mysql_loop_delay);
    sleep(params->mysql_loop_delay);
  }

  return NULL;
}

int mysql_setup(arpwatch_params *params) {
  DEBUG_PRINT("MySQL client version: %s\n", mysql_get_client_info());

  // Setup thread data

  pthread_t threadId;
  int err = pthread_create(&threadId, NULL,
                           &mysql_thread, (void *)params);
  if (err) {
    ERROR_COMMENT("Unable to create thread.");
    return -1;
  }

  return 0;
}
