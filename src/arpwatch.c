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

int debug_flag = 0;

int read_global_config(arpwatch_params *params, const char *filename) {
  config_t cfg;
  const char *str;
  int rtn = -1;

  config_init(&cfg);

  if (!config_read_file(&cfg, filename)) {
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

  if (config_lookup_string(&cfg, "password", &str)) {
    strncpy(params->password, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No password defined in config file\n");
    goto _error;
  }

  if (config_lookup_string(&cfg, "database", &str)) {
    strncpy(params->database, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No database defined in config file\n");
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

  config_setting_t *setting = config_lookup(&cfg, "interfaces");
  if (setting == NULL) {
    ERROR_COMMENT("No interfaces in config file.\n");
    goto _error;
  }

  // Number of interfaces
  params->num_interface = config_setting_length(setting);

  rtn = 0;

  NOTICE_PRINT("Read global info from config file %s\n",
               filename);

_error:
  config_destroy(&cfg);
  return rtn;
}

int read_interface_config(arpwatch_params *params,
                          const char* filename,
                          int interface_num) {
  config_t cfg;
  const char *str;
  int rtn = -1;

  config_init(&cfg);

  if (!config_read_file(&cfg, filename)) {
    ERROR_PRINT("%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
    goto _error;
  }

  config_setting_t *setting = config_lookup(&cfg, "interfaces");
  if (setting == NULL) {
    ERROR_COMMENT("No interfaces in config file.\n");
    goto _error;
  }
  config_setting_t *interface = config_setting_get_elem(setting, interface_num);
  DEBUG_PRINT("Instance number = %d\n", interface_num);

  if (config_setting_lookup_string(interface, "device", &str)) {
    strncpy(params->device, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No device defined in config file\n");
    goto _error;
  }

  if (config_setting_lookup_string(interface, "label", &str)) {
    strncpy(params->label, str, ARPWATCH_CONFIG_MAX_STRING);
  } else {
    ERROR_COMMENT("No label defined in config file\n");
    goto _error;
  }

  if (!config_setting_lookup_bool(interface, "ignore_tagged",
                                  &params->ignore_tagged)) {
    params->ignore_tagged = 0;
  }

  if (!config_setting_lookup_bool(interface, "arp_requests",
                                  &params->arp_requests)) {
    params->arp_requests = 1;
  }

  if (!config_setting_lookup_int(interface, "arp_loop_delay",
                                 &params->arp_loop_delay)) {
    params->arp_loop_delay = ARPWATCH_ARP_LOOP_DELAY;
  }

  if (!config_setting_lookup_int(interface, "arp_delay",
                                 &params->arp_delay)) {
    params->arp_delay = ARPWATCH_ARP_DELAY;
  }

  if (!config_setting_lookup_int(interface, "native_vlan",
                                 &params->native_vlan)) {
    params->native_vlan = 0;
  }

  //
  // Now process networks per interface
  //

  config_setting_t *s = config_setting_lookup(interface, "networks");
  if (s== NULL) {
    ERROR_COMMENT("No networks in config file.\n");
    goto _error;
  }

  params->num_network = config_setting_length(s);  // Number of interfaces
  DEBUG_PRINT("Configuring %d networks\n", params->num_network);

  params->network = (arpwatch_network*)
    malloc(sizeof(arpwatch_network) * params->num_network);

  if (!params->network) {
    ERROR_COMMENT("Unable to allocate memory for networks\n");
    goto _error;
  }

  //
  // Loop over all networks
  //

  for (int i = 0; i < params->num_network; i++) {
    config_setting_t *net = config_setting_get_elem(s, i);

    if (config_setting_lookup_string(net, "ipaddress", &str)) {
      struct in_addr addr;
      if (!inet_aton(str, &addr)) {
        ERROR_COMMENT("Invalid ip address specified\n");
        goto _error;
      }
      params->network[i].ipaddress = addr.s_addr;
    } else {
      ERROR_COMMENT("No ipaddress defined in config file\n");
      goto _error;
    }

    if (config_setting_lookup_string(net, "subnet", &str)) {
      struct in_addr addr;
      if (!inet_aton(str, &addr)) {
        ERROR_COMMENT("Invalid subnet mask specified\n");
        goto _error;
      }
      params->network[i].subnet = addr.s_addr;
    } else {
      ERROR_COMMENT("No subnet defined in config file\n");
      goto _error;
    }

    if (!config_setting_lookup_int(net, "vlan",
                                   &params->network[i].vlan)) {
      params->network[i].vlan = 0;
    }

    if (!config_setting_lookup_int(net, "vlan_pri",
                                   &params->network[i].vlan_pri)) {
      params->network[i].vlan_pri = 0;
    }

    if (!config_setting_lookup_int(net, "vlan_dei",
                                   &params->network[i].vlan_dei)) {
      params->network[i].vlan_dei = 0;
    }

    if (config_setting_lookup_string(net, "ipaddress_source", &str)) {
      struct in_addr addr;
      if (!inet_aton(str, &addr)) {
        ERROR_COMMENT("Invalid ipaddress_source specified\n");
        goto _error;
      }
      params->network[i].ipaddress_source = addr.s_addr;
    } else {
      params->network[i].ipaddress_source = 0;
    }
  }

  rtn = 0;

_error:
  config_destroy(&cfg);
  NOTICE_PRINT("Read interface %d from config file %s\n",
             interface_num, ARPWATCH_CONFIG_FILE);
  return rtn;
}

int main(int argc, char *argv[]) {
  arpwatch_params params;
  char *config_filename = ARPWATCH_CONFIG_FILE;

  // Process command line options

  while (1) {
    static struct option long_options[] = {
      // These options set a flag
      {"debug",   no_argument,       &debug_flag, 1},
      {"breif",   no_argument,       &debug_flag, 0},
      {"config",  required_argument, 0, 'c'},
      {"version", no_argument,       0, 'v'},
      {0, 0, 0, 0}
    };

    int option_index = 0;

    int c = getopt_long(argc, argv, "bdvc:",
                        long_options, &option_index);

    if (c == -1) {
      break;
    }

    switch (c) {
      case 0:
        // If this option set a flag, do nothing else now.
        if (long_options[option_index].flag != 0) {
          break;
        }
        fprintf(stderr, "option %s", long_options[option_index].name);
        if (optarg)
          fprintf(stderr, " with arg %s", optarg);
        fprintf(stderr, "\n");
        break;

      case 'c':
        // Set the config file
        config_filename = optarg;
        break;

      case 'v':
        // Print Version info
        fprintf(stderr, "Version : %s\n", ARPTOOLS_GIT_VERSION);
        exit(0);
        break;

      case '?':
        exit(-1);
        break;

      default:
        exit(-1);
    }
  }

  strncpy(params.program,
          ARPWATCH_PCAP_PROGRAM,
          ARPWATCH_CONFIG_MAX_STRING);

  DEBUG_PRINT("git rev     = %s\n", ARPTOOLS_GIT_REV);
  DEBUG_PRINT("git branch  = %s\n", ARPTOOLS_GIT_BRANCH);
  DEBUG_PRINT("git version = %s\n", ARPTOOLS_GIT_VERSION);

  NOTICE_PRINT("Startup (version = %s)\n", ARPTOOLS_GIT_VERSION);

  if (read_global_config(&params, config_filename)) {
    ERROR_COMMENT("Error reading config file\n");
    return EXIT_FAILURE;
  }

  int pid;
  for (int i = 0; i < params.num_interface; i++) {
    pid = fork();
    if (pid < 0) {
      ERROR_COMMENT("Error in fork()\n");
      exit(EXIT_FAILURE);
    } else if (pid == 0) {
      DEBUG_PRINT("Child (%d): %d from %d\n", i, getpid(), getppid());

      if (read_interface_config(&params, config_filename, i)) {
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

      // Ok if we get here, cleanup memory

      buffer_free(&(params.data_buffer));
      free(params.network);

      exit(EXIT_SUCCESS);
    }
  }

  // Now wait for all child processes to exit

  while (wait(NULL) > 0) {
    continue;
  }

  return EXIT_SUCCESS;
}
