local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects an NTP service on UDP port 123 and parses the NTP header from the
reply to report the leap indicator, version, mode and stratum.

This is an enhancement of a basic present/absent check: instead of only
reporting that a reply was received, it reads the first bytes of the NTP
packet and tells you what the server is announcing about itself. It sends a
single standard NTP client request and reads the reply -- discovery only.
]]

---
-- @usage
-- nmap -sU -p 123 --script ntp-detect <target>
--
-- @output
-- PORT    STATE SERVICE
-- 123/udp open  ntp
-- | ntp-detect:
-- |   NTP service: detected
-- |   Response size: 48 bytes
-- |   Leap indicator: 0
-- |   Version: 4
-- |   Mode: 4
-- |_  Stratum: 2

author = "Samyuktha S."
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

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
  local li      = (first >> 6) & 0x03
  local version = (first >> 3) & 0x07
  local mode    = first & 0x07
  local stratum = string.byte(response, 2)

  local out = stdnse.output_table()
  out["NTP service"]    = "detected"
  out["Response size"]  = #response .. " bytes"
  out["Leap indicator"] = li
  out["Version"]        = version
  out["Mode"]           = mode
  out["Stratum"]        = stratum
  return out
end
