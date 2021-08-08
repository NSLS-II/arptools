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

#include "debug.h"
#include "buffer.h"
#include "mysql.h"
#include "utils.h"
#include "arpwatch.h"

void mysql_print_error(MYSQL *con) {
  ERROR_PRINT("MySQL Error : %s\n", mysql_error(con));
}

void * mysql_thread(void * arg) {
  arpwatch_params *params = (arpwatch_params *) arg;

  NOTICE_COMMENT("Starting mysql thread\n");

  for (;;) {
    MYSQL *con = mysql_init(NULL);
    if (!con) {
      mysql_print_error(con);
      goto _error;
    }

    if (mysql_real_connect(con, params->hostname,
                           params->username,
                           params->password,
                           params->database,
                           0, NULL, 0) == NULL) {
      mysql_print_error(con);
      goto _error;
    }

    arp_data *arp = buffer_get_tail(&(params->data_buffer), 0);

    while (arp) {
      char sql_buffer[100000];
      char time_buffer[256];
      char hostname[256];
      char vlan[256];

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

      struct  hostent *he = gethostbyaddr(&arp->ip_addr, sizeof(arp->ip_addr),
                                          AF_INET);
      if (he) {
        strncpy(hostname, he->h_name, sizeof(hostname));
      } else {
        strncpy(hostname, "(none)", sizeof(hostname));
      }

      DEBUG_PRINT("Hostname : %s\n", hostname);

      if (arp->vlan == NO_VLAN_TAG) {
        snprintf(vlan, sizeof(vlan), "NULL");
      } else {
        snprintf(vlan, sizeof(vlan), "%d", arp->vlan);
      }

      const char *hw_addr = int_to_mac(arp->hw_addr);
      const char *ip_addr = inet_ntoa(arp->ip_addr);

      if ((arp->type == BUFFER_TYPE_ARP_SRC) ||
          (arp->type == BUFFER_TYPE_ARP_DST) ||
          (arp->type == BUFFER_TYPE_UDP) ||
          (arp->type == BUFFER_TYPE_IP)) {
        int type_arp = 0;
        int type_udp = 0;

        if ((arp->type == BUFFER_TYPE_ARP_SRC) ||
            (arp->type == BUFFER_TYPE_ARP_DST)) {
          type_arp = 1;
        }
        if (arp->type == BUFFER_TYPE_UDP) {
          type_udp = 1;
        }

        snprintf(sql_buffer, sizeof(sql_buffer),
                "INSERT INTO arpdata "
                "(hw_address, ip_address, location, "
                "label, last_seen, hostname, "
                "type_arp, type_udp, vlan) "
                "VALUES ('%s', '%s', '%s', '%s', "
                "'%s', '%s', %d, %d, %s) "
                "ON DUPLICATE KEY UPDATE "
                "ip_address = '%s', "
                "location = '%s', "
                "label = '%s', "
                "last_seen = '%s', "
                "hostname = '%s', "
                "type_arp = %d, "
                "type_udp = %d, "
                "vlan = %s;",
                hw_addr,
                ip_addr, params->location, params->label,
                time_buffer, hostname,
                type_arp, type_udp, vlan,
                ip_addr, params->location, params->label,
                time_buffer, hostname,
                type_arp, type_udp, vlan);

        DEBUG_PRINT("ARP/IP/UDP %d SQL query : %s\n", arp->type, sql_buffer);

        if (mysql_real_query(con, sql_buffer, strlen(sql_buffer))) {
          mysql_print_error(con);
        }
      } else if (arp->type == BUFFER_TYPE_DHCP) {
        snprintf(sql_buffer, sizeof(sql_buffer),
                "INSERT INTO arpdata "
                "(hw_address, location, label, "
                "last_seen, dhcp_name, type_dhcp, vlan) "
                "VALUES ('%s', '%s', '%s', '%s', '%s', true, %s) "
                "ON DUPLICATE KEY UPDATE "
                "location = '%s', "
                "label = '%s', "
                "last_seen = '%s', "
                "dhcp_name = '%s', "
                "type_dhcp = true, "
                "vlan = %s;",
                hw_addr,
                params->location, params->label, time_buffer,
                arp->dhcp_name, vlan,
                params->location, params->label, time_buffer,
                arp->dhcp_name, vlan);

        DEBUG_PRINT("DNS NAME SQL query : %s\n", sql_buffer);

        if (mysql_real_query(con, sql_buffer, strlen(sql_buffer))) {
          mysql_print_error(con);
        }
      } else if (arp->type == BUFFER_TYPE_UNKNOWN) {
        snprintf(sql_buffer, sizeof(sql_buffer),
                "INSERT INTO arpdata "
                "(hw_address, location, label, "
                "last_seen, vlan) "
                "VALUES ('%s', '%s', '%s', '%s', %s) "
                "ON DUPLICATE KEY UPDATE "
                "location = '%s', "
                "label = '%s', "
                "last_seen = '%s', "
                "vlan = %s;",
                hw_addr,
                params->location, params->label, time_buffer, vlan,
                params->location, params->label, time_buffer, vlan);

        DEBUG_PRINT("Unknown name SQL query : %s\n", sql_buffer);

        if (mysql_real_query(con, sql_buffer, strlen(sql_buffer))) {
          mysql_print_error(con);
        }
      } else {
        ERROR_PRINT("Unknown packet type %d\n", arp->type);
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
