local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects an NTP service on UDP port 123, with two usability enhancements over
a basic check: the socket timeout can be set with the ntp-detect.timeout
script-arg, and the detected NTP version and stratum are fed back into Nmap's
own service/version detection so they appear in the normal VERSION column.

Discovery only -- it sends one standard NTP client request and reads the
reply.
]]

---
-- @usage
-- nmap -sU -p 123 --script ntp-detect-version <target>
-- nmap -sU -p 123 --script ntp-detect-version --script-args ntp-detect.timeout=5000 <target>
--
-- @output
-- PORT    STATE SERVICE VERSION
-- 123/udp open  ntp     NTP v4 (stratum 2)
-- | ntp-detect-version:
-- |   NTP service: detected
-- |   Version: 4
-- |   Stratum: 2
-- |_  Timeout used (ms): 3000

author = "Samyuktha S."
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.version_port_or_service(123, "ntp", "udp")

action = function(host, port)
  local timeout = tonumber(stdnse.get_script_args("ntp-detect.timeout")) or 3000

  local socket = nmap.new_socket()
  socket:set_timeout(timeout)

  local ok = socket:connect(host, port, "udp")
  if not ok then
    return "NTP service not reachable"
  end

  -- Standard NTP client request (LI=0, VN=3, Mode=3)
  local request = string.char(0x1b) .. string.rep(string.char(0x00), 47)
  socket:send(request)

  local status, response = socket:receive()
  socket:close()

  if not (status and response and #response >= 2) then
    return "NTP service did not respond"
  end

  local first   = string.byte(response, 1)
  local version = (first >> 3) & 0x07
  local stratum = string.byte(response, 2)

  -- Feed the result into Nmap's service/version detection
  port.version = port.version or {}
  port.version.name    = "ntp"
  port.version.product = "NTP v" .. version
  port.version.version = "stratum " .. stratum
  nmap.set_port_version(host, port, "hardmatched")

  local out = stdnse.output_table()
  out["NTP service"]       = "detected"
  out["Version"]           = version
  out["Stratum"]           = stratum
  out["Timeout used (ms)"] = timeout
  return out
end
