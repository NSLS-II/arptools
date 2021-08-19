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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <libconfig.h>
#include <sys/wait.h>

#include "buffer.h"
#include "mysql.h"
#include "debug.h"
#include "arp.h"
#include "capture.h"
#include "arpwatch.h"

extern const char* ARPTOOLS_GIT_REV;
extern const char* ARPTOOLS_GIT_BRANCH;
extern const char* ARPTOOLS_GIT_VERSION;

int read_global_config(arpwatch_params *params) {
  config_t cfg;
  const char *str;
  int rtn = -1;

  config_init(&cfg);

  if (!config_read_file(&cfg, ARPWATCH_CONFIG_FILE)) {
    ERROR_PRINT("%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
    goto _error;
  }

  if (config_lookup_string(&cfg, "hostname", &str)) {
    strncpy(params->hostname, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No hostname defined in config file\n");
    goto _error;
  }

  if (config_lookup_string(&cfg, "username", &str)) {
    strncpy(params->username, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No username defined in config file\n");
    goto _error;
  }

  if (config_lookup_string(&cfg, "database", &str)) {
    strncpy(params->database, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No database defined in config file\n");
    goto _error;
  }

  if (config_lookup_string(&cfg, "password", &str)) {
    strncpy(params->password, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No password defined in config file\n");
    goto _error;
  }

  if (config_lookup_string(&cfg, "location", &str)) {
    strncpy(params->location, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No location defined in config file\n");
    goto _error;
  }

  if (!config_lookup_int(&cfg, "mysql_loop_delay", &params->mysql_loop_delay)) {
    params->mysql_loop_delay = ARPWATCH_MYSQL_LOOP_DELAY;
  }

  if (!config_lookup_int(&cfg, "pcap_timeout", &params->pcap_timeout)) {
    params->pcap_timeout = ARPWATCH_PCAP_TIMEOUT;
  }

  if (!config_lookup_int(&cfg, "buffer_size", &params->buffer_size)) {
    params->buffer_size = ARPWATCH_BUFFER_SIZE;
  }

  config_setting_t *setting = config_lookup(&cfg, "instances");
  if (setting == NULL) {
    ERROR_COMMENT("No instances in config file.\n");
    goto _error;
  }

  params->num_instance = config_setting_length(setting);  // Number of instances

  rtn = 0;

_error:
  config_destroy(&cfg);
  NOTICE_PRINT("Read global info from config file %s\n",
             ARPWATCH_CONFIG_FILE);
  return rtn;
}

int read_instance_config(arpwatch_params *params, int instance_num) {
  config_t cfg;
  const char *str;
  int rtn = -1;

  config_init(&cfg);

  if (!config_read_file(&cfg, ARPWATCH_CONFIG_FILE)) {
    ERROR_PRINT("%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
    goto _error;
  }

  config_setting_t *setting = config_lookup(&cfg, "instances");
  if (setting == NULL) {
    ERROR_COMMENT("No instances in config file.\n");
    goto _error;
  }
  config_setting_t *instance = config_setting_get_elem(setting, instance_num);
  DEBUG_PRINT("Instance number = %d\n", instance_num);

  if (config_setting_lookup_string(instance, "interface", &str)) {
    strncpy(params->iface, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No interface defined in config file\n");
    goto _error;
  }

  if (config_setting_lookup_string(instance, "label", &str)) {
    strncpy(params->label, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No label defined in config file\n");
    goto _error;
  }

  if (config_setting_lookup_string(instance, "ipaddress", &str)) {
    struct in_addr addr;
    if (!inet_aton(str, &addr)) {
      ERROR_COMMENT("Invalid ip address specified\n");
      goto _error;
    }
    params->ipaddress = addr.s_addr;
  } else {
    ERROR_COMMENT("No ipaddress defined in config file\n");
    goto _error;
  }

  if (config_setting_lookup_string(instance, "subnet", &str)) {
    struct in_addr addr;
    if (!inet_aton(str, &addr)) {
      ERROR_COMMENT("Invalid subnet mask specified\n");
      goto _error;
    }
    params->subnet = addr.s_addr;
  } else {
    ERROR_COMMENT("No subnet defined in config file\n");
    goto _error;
  }

  if (!config_setting_lookup_bool(instance, "ignore_tagged",
                                  &params->ignore_tagged)) {
    params->ignore_tagged = 0;
  }

  if (!config_setting_lookup_bool(instance, "arp_requests",
                                  &params->arp_requests)) {
    params->arp_requests = 1;
  }

  if (!config_setting_lookup_int(instance, "arp_loop_delay",
                                 &params->arp_loop_delay)) {
    params->arp_loop_delay = ARPWATCH_ARP_LOOP_DELAY;
  }

  if (!config_setting_lookup_int(instance, "arp_delay",
                                 &params->arp_delay)) {
    params->arp_delay = ARPWATCH_ARP_DELAY;
  }

  if (!config_setting_lookup_bool(instance, "filter_self",
                                  &params->filter_self)) {
    params->filter_self = 0;
  }

  params->vlan = 170;

  rtn = 0;

_error:
  config_destroy(&cfg);
  NOTICE_PRINT("Read instance %d from config file %s\n",
             instance_num, ARPWATCH_CONFIG_FILE);
  return rtn;
}

int main(int argc, char *argv[]) {
  arpwatch_params params;
  (void)argc;
  (void)argv;

  DEBUG_PRINT("git rev     = %s\n", ARPTOOLS_GIT_REV);
  DEBUG_PRINT("git branch  = %s\n", ARPTOOLS_GIT_BRANCH);
  DEBUG_PRINT("git version = %s\n", ARPTOOLS_GIT_VERSION);

  NOTICE_PRINT("Startup (version = %s)\n", ARPTOOLS_GIT_VERSION);

  strncpy(params.program,
          ARPWATCH_PCAP_PROGRAM,
          ARPWATCH_CONFIG_MAX_STRING);

  if (read_global_config(&params)) {
    ERROR_COMMENT("Error reading config file\n");
    return EXIT_FAILURE;
  }

  int pid;
  for (int i = 0; i < params.num_instance; i++) {
    pid = fork();
    if (pid < 0) {
      ERROR_COMMENT("Error in fork()\n");
      exit(EXIT_FAILURE);
    } else if (pid == 0) {
      DEBUG_PRINT("Child (%d): %d from %d\n", i, getpid(), getppid());

      if (read_instance_config(&params, i)) {
        ERROR_COMMENT("Error reading config file\n");
        exit(EXIT_FAILURE);
      }

      // Setup Buffer

      if (buffer_init(&(params.data_buffer),
                      params.buffer_size, 1) != BUFFER_NOERR) {
        ERROR_COMMENT("buffer_init(): ERROR");
        exit(EXIT_FAILURE);
      }

      mysql_setup(&params);
      if (params.arp_requests) {
        arp_setup(&params);
      }
      capture_start(&params);

      exit(EXIT_SUCCESS);
    }
  }

  // Now wait for all child processes to exit

  while (wait(NULL) > 0) {
    continue;
  }

  return EXIT_SUCCESS;
}
