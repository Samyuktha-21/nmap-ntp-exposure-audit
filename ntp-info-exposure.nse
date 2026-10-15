local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
NTP information-disclosure exposure auditor.

Builds on the idea of Nmap's built-in ntp-info script. It sends a single
mode-6 "read variables" (READVAR) control request and, instead of only
listing the variables, it judges how much an anonymous client can learn and
assigns a scored exposure rating. Fields such as the exact ntpd build
(version), the operating system (system) and the processor architecture are
treated as information disclosure, because they help an attacker fingerprint
and target the host.

Detection only: one standard query is sent and the reply is read. The script
makes no changes to the server and generates no traffic toward third parties.
]]

---
-- @usage
-- nmap -sU -p 123 --script ntp-info-exposure <target>
--
-- @output
-- PORT    STATE SERVICE
-- 123/udp open  ntp
-- | ntp-info-exposure:
-- |   NTP control plane: answered anonymous read-variables request
-- |   Exposure score: 9
-- |   Exposure rating: HIGH
-- |   Disclosed fields:
-- |     processor = x86_64  (CPU architecture is revealed)
-- |     refid = 195.145.119.188  (upstream reference clock is revealed)
-- |     system = Linux/5.15.0  (operating system / kernel is revealed)
-- |     version = ntpd 4.2.8p15  (exact ntpd build is revealed)
-- |_  Recommendation: restrict queries in ntp.conf (see below)

author = "Samyuktha S."
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(123, "ntp", {"udp", "tcp"})

-- Fields that leak useful fingerprinting information to an anonymous client,
-- with the weight each one adds to the exposure score.
local SENSITIVE = {
  version   = {3, "exact ntpd build is revealed"},
  system    = {3, "operating system / kernel is revealed"},
  processor = {2, "CPU architecture is revealed"},
  refid     = {1, "upstream reference clock is revealed"},
}

-- Parse the comma-separated key=value list returned by a mode-6 readvar.
local function parse_vars(data)
  local vars = {}
  for k, v in string.gmatch(data, "([%w_%-%.]+)=([^,]*)") do
    vars[k:lower()] = (v:gsub('^%s*"?', ''):gsub('"?%s*$', ''))
  end
  return vars
end

action = function(host, port)
  -- mode-6 (control) read-variables request, as used by ntp-info
  local rlreq = string.char(0x16, 0x02, 0x00, 0x01, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

  local status, resp = comm.exchange(host, port, rlreq, {timeout = 5000})
  if not status or not resp or #resp < 12 then
    return "NTP control query not answered - server may set 'noquery' (good)"
  end

  -- Data is length-prefixed (2 bytes) after the 10-byte control header.
  local ok, data = pcall(string.unpack, ">s2", resp, 11)
  if not ok or not data then
    return "NTP responded but no readable variables were returned"
  end

  local vars = parse_vars(data)

  local score = 0
  local findings = {}
  for field, meta in pairs(SENSITIVE) do
    if vars[field] and vars[field] ~= "" then
      score = score + meta[1]
      table.insert(findings, string.format("%s = %s  (%s)", field, vars[field], meta[2]))
    end
  end
  table.sort(findings)

  local rating
  if score >= 6 then rating = "HIGH"
  elseif score >= 3 then rating = "MEDIUM"
  elseif score >= 1 then rating = "LOW"
  else rating = "MINIMAL" end

  local out = stdnse.output_table()
  out["NTP control plane"] = "answered anonymous read-variables request"
  out["Exposure score"] = score
  out["Exposure rating"] = rating
  out["Disclosed fields"] = (#findings > 0) and findings or "none of the tracked sensitive fields"
  out["Recommendation"] =
    "Restrict queries, e.g. 'restrict default kod nomodify notrap nopeer noquery' in ntp.conf"
  return out
end
