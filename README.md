# NTP Exposure Audit — Nmap NSE Scripts

Two Nmap Scripting Engine (NSE) scripts that enhance the built-in
`ntp-info.nse` into **scored NTP exposure auditors**. Instead of only listing
what an NTP server reports, they judge *how exposed* the server is and give a
rating an analyst can act on.

Both scripts are **detection only** — they send one or two small, standard NTP
queries and read the reply. They make no changes to the target and send no
traffic toward any third party. Use them only against hosts you own or are
authorised to test.

## Scripts

| Script | Enhancement | What it reports |
|--------|-------------|-----------------|
| `ntp-info-exposure.nse` | Information-disclosure auditor | Scores how much an anonymous client can fingerprint the host (ntpd build, OS, CPU, upstream refid) and rates it LOW / MEDIUM / HIGH. |
| `ntp-amp-exposure.nse` | Amplification auditor | Detects whether the server answers mode-6 readvar and mode-7 `monlist` queries, measures the response-to-request size ratio, and flags the classic CVE-2013-5211 amplification exposure. |

## Usage

```
# Information-disclosure exposure
nmap -sU -p 123 --script ./ntp-info-exposure.nse <target>

# Amplification exposure
nmap -sU -p 123 --script ./ntp-amp-exposure.nse <target>
```

To run them like any other NSE script, copy them into the Nmap `scripts/`
directory and run `nmap --script-updatedb`.

## Base / reference script

These build on the behaviour of Nmap's built-in `ntp-info.nse`, which sends a
mode-3 time request and a mode-6 read-variables request to collect NTP
variables. The reference script ships with Nmap and is not included here.

## Conclusion

Starting from Nmap's built-in `ntp-info` and asking "so how bad is this?" turns
a simple variable dump into two auditors that give a verdict: one scores how
much an NTP server reveals about itself (information disclosure), and the other
flags whether it can be abused to amplify an attack (CVE-2013-5211). The same
NTP conversation, read through a security lens and scored, becomes something a
defender can prioritise and fix — while the scripts stay honest about what they
do and never attack a third party.

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
- References: the official Nmap NSE documentation, the NTP RFCs, and the
  CVE-2013-5211 advisory.

## Author

Samyuktha S.

## License

Same as Nmap — see https://nmap.org/book/man-legal.html
