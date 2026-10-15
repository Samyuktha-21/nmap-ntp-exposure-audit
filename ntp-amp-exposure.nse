local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
NTP amplification exposure auditor.

Checks whether an NTP server can be abused as a traffic-amplification
reflector in UDP DDoS attacks. It sends two small, standard queries as a
normal client -- a mode-6 "read variables" request and the legacy mode-7
"monlist" request (ntpdc MON_GETLIST_1) -- and measures how large the
server's reply is compared with the request. A server that answers monlist
is the classic CVE-2013-5211 amplification exposure.

Detection only: one request of each type is sent and the first reply is
measured. The script never sends amplified traffic toward any third party;
it only reports whether this server WOULD be abusable, so the owner can fix
it.
]]

---
-- @usage
-- nmap -sU -p 123 --script ntp-amp-exposure <target>
--
-- @output
-- PORT    STATE SERVICE
-- 123/udp open  ntp
-- | ntp-amp-exposure:
-- |   Amplification exposure: server answers unauthenticated status queries
-- |   Findings:
-- |     mode-6 readvar answered: 260-byte reply to 12-byte request (x21.7)
-- |     mode-7 MONLIST answered: 440-byte reply to 48-byte request (x9.2) - CVE-2013-5211
-- |   Largest amplification (first packet): x21.7
-- |   Exposure rating: HIGH
-- |   Note: real-world monlist amplification is far larger across many reply packets
-- |_  Recommendation: disable monlist, upgrade ntpd, restrict queries (see below)

author = "Samyuktha S."
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service(123, "ntp", {"udp", "tcp"})

local function probe(host, port, req)
  local status, resp = comm.exchange(host, port, req, {timeout = 5000})
  if status and resp and #resp > 0 then
    return #resp
  end
  return 0
end

action = function(host, port)
  -- mode-6 (control) read-variables request (12 bytes)
  local rlreq = string.char(0x16, 0x02, 0x00, 0x01, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  -- mode-7 monlist request: version 2, mode 7, impl 3 (XNTPD), reqcode 42 (48 bytes)
  local monreq = string.char(0x17, 0x00, 0x03, 0x2a) .. string.rep(string.char(0x00), 44)

  local rl_resp  = probe(host, port, rlreq)
  local mon_resp = probe(host, port, monreq)

  local findings = {}
  local worst = 0

  if rl_resp > 0 then
    local factor = rl_resp / #rlreq
    if factor > worst then worst = factor end
    table.insert(findings, string.format(
      "mode-6 readvar answered: %d-byte reply to %d-byte request (x%.1f)",
      rl_resp, #rlreq, factor))
  end

  if mon_resp > 0 then
    local factor = mon_resp / 48
    if factor > worst then worst = factor end
    table.insert(findings, string.format(
      "mode-7 MONLIST answered: %d-byte reply to 48-byte request (x%.1f) - CVE-2013-5211",
      mon_resp, factor))
  end

  if #findings == 0 then
    return "NTP server did not answer mode-6/mode-7 queries - not abusable for amplification (good)"
  end

  local rating
  if mon_resp > 0 or worst >= 5 then rating = "HIGH"
  elseif worst >= 2 then rating = "MEDIUM"
  else rating = "LOW" end

  local out = stdnse.output_table()
  out["Amplification exposure"] = "server answers unauthenticated status queries"
  out["Findings"] = findings
  out["Largest amplification (first packet)"] = string.format("x%.1f", worst)
  out["Exposure rating"] = rating
  out["Note"] = "Real-world monlist amplification is far larger across many reply packets"
  out["Recommendation"] =
    "Disable monlist (ntpdc), upgrade ntpd >= 4.2.7p26, and set 'restrict default ... noquery'"
  return out
end
