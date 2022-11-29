#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                 (c) Copyright 2021-2022 Ward
#
#====================================================================

# This file has some codes that need SSL related DLL to run.
# Compile this file to ssl_test.exe and use embedded_ssl_test.nim to test it.
#
#   nim c -d:ssl ssl_test
#

import httpclient

var client = newHttpClient()
echo client.getContent("https://google.com")[0..127]
