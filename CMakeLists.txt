#
#  arptools
#
#  Stuart B. Wilkins, Brookhaven National Laboratory
#
#
#  BSD 3-Clause License
#
#  Copyright (c) 2021, Brookhaven Science Associates
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  1. Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#
#  3. Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
#  THE POSSIBILITY OF SUCH DAMAGE.
#

cmake_minimum_required(VERSION 3.10)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(PreventInSourceBuilds)
include(systemdservice)

# set the project name
project(arptools C)

# Options
option(CPPLINT_CHECK "Check CXX Source for Formatting" ON)
option(PEDANTIC "Compile with pedantic warnings" ON)
option(DEBUG "Show debug comments" OFF)

# Add options
add_compile_options(-fPIE)

if(PEDANTIC)
  add_compile_options(-pedantic -Wall -Wextra -Werror)
endif()

if(DEBUG)
  add_compile_options(-DDEBUG)
endif()

if(CPPLINT_CHECK)
  include(cpplint)
  cpplint_add_subdirectory(src)
  message(STATUS "Checking CXX Code via cpplint")
endif()

# Add __FILENAME__ with short path
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")

# Add a custom command that produces version.c, plus
# a dummy output that's not actually produced, in order
# to force version.cmake to always be re-run before the build
add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/version.c
  ${CMAKE_BINARY_DIR}/_version.c
  COMMAND ${CMAKE_COMMAND} -P
  ${CMAKE_SOURCE_DIR}/cmake/version.cmake
)

# add the executable
add_executable(arpwatch src/arpwatch.c
                        src/fifo.c
                        src/mysql.c
                        src/arp.c
                        src/utils.c
                        src/capture.c
                        version.c)

add_custom_target(version_info DEPENDS ${CMAKE_BINARY_DIR}/version.c)

find_library(PCAP_LIBRARY pcap REQUIRED)
find_library(NET_LIBRARY net REQUIRED)

execute_process(COMMAND mysql_config --cflags
    OUTPUT_VARIABLE MYSQL_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND mysql_config --libs
    OUTPUT_VARIABLE MYSQL_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE)

target_compile_options(arpwatch PRIVATE ${MYSQL_CFLAGS})
#target_link_libraries(arpwatch PRIVATE ${PCAP_LIBRARY} ${NET_LIBRARY} ${MYSQL_LIBS} -pthread)
target_link_libraries(arpwatch PRIVATE pcap net pthread config ${MYSQL_LIBS})

# Set C standard
set_property(TARGET arpwatch PROPERTY C_STANDARD 11)

# Install

install(TARGETS arpwatch RUNTIME DESTINATION bin/)
if (SYSTEMD_FOUND)
  configure_file(systemd/arpwatch.service.in ${CMAKE_CURRENT_BINARY_DIR}/arpwatch.service @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/arpwatch.service
    DESTINATION ${SYSTEMD_SERVICES_INSTALL_DIR}
    COMPONENT data
  )
endif (SYSTEMD_FOUND)
