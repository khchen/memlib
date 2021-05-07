#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

import httpclient
var client = newHttpClient()
echo client.getContent("https://google.com")[0..127]

