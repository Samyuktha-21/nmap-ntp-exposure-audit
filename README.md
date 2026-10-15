# NTP Detection — Nmap NSE Scripts

Two Nmap Scripting Engine (NSE) scripts that enhance basic NTP detection on
UDP port 123. They build on the idea of Nmap's built-in `ntp-info.nse`: instead
of only confirming that an NTP service replied, they parse the NTP header and
report useful details about the server.

Both scripts are **discovery / safe** — they send one standard NTP client
request and read the reply. They make no changes to the target. Use them only
against hosts you own or are authorised to test.

## Scripts

| Script | Enhancement | What it reports |
|--------|-------------|-----------------|
| `ntp-detect.nse` | Header parsing | Confirms the NTP service and reports leap indicator, version, mode and stratum from the reply. |
| `ntp-detect-version.nse` | Timeout arg + version detection | Adds a configurable timeout (`ntp-detect.timeout`) and feeds the NTP version and stratum into Nmap's service/version (`-sV`) output. |

## Usage

```
# Header-parsing detection
nmap -sU -p 123 --script ./ntp-detect.nse <target>

# With version detection and a custom timeout
nmap -sU -p 123 --script ./ntp-detect-version.nse --script-args ntp-detect.timeout=5000 <target>
```

To run them like any other NSE script, copy them into the Nmap `scripts/`
directory and run `nmap --script-updatedb`.

## Base / reference script

These build on the behaviour of Nmap's built-in `ntp-info.nse`, which queries
an NTP server for its time and configuration variables. The reference script
ships with Nmap and is not included here.

## Conclusion

Starting from a plain "is an NTP service here?" check, these two scripts turn a
bare detection into something more useful: one reads the NTP header and reports
the server's version, mode and stratum; the other makes the probe configurable
and wires the result into Nmap's own version detection. The same single NTP
request, parsed properly, gives an analyst real detail instead of just a yes/no.

## Acknowledgements

- School of Computer Science and Engineering (SCOPE), Vellore Institute of
  Technology, Chennai — for offering the course Cyber Security during Fall
  Semester 2026-2027 with an industry-standard syllabus.
- Course Faculty: Dr. T. Subbulakshmi, Professor, SCOPE, VIT Chennai — for the
  guidance throughout the course.
- Gordon Lyon ("Fyodor"), the founder of Nmap, and Richard Sammet, the author
  of the built-in `ntp-info.nse` — for the tools and the reference script this
  work builds on.
- My peers, friends and family — for their suggestions, testing help and
  constant support.
- References: the official Nmap NSE documentation and the NTP RFCs.

## Author

Samyuktha S.

## License

Same as Nmap — see https://nmap.org/book/man-legal.html
