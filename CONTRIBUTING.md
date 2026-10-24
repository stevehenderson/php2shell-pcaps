# Contributing

This repository holds packet captures from vulnerability labs. The bar
for what goes in here is high, because a bad pcap can leak real network
topology, credentials, or PII that a contributor did not intend to share.

## PCAP size

- **Target:** under 5 MB per pcap. The current captures are 293-294 KB.
- **Hard limit:** 50 MB. Above that, split by phase (baseline vs attack)
  or by tap point and document the split in the README.
- Use `editcap` to trim unused time ranges before committing:

  ```bash
  # Keep only packets between 10s and 60s of the capture
  editcap -A 10 -B 60 input.pcap trimmed.pcap
  ```

- Use a BPF filter at capture time, not after. Capture only what the
  analysis needs:

  ```bash
  tcpdump -i eth0 -nn -s 0 -w out.pcap "tcp port 80"
  ```

  Not `tcpdump -i eth0 -w out.pcap` with no filter. An unfiltered capture
  of a Docker bridge or home NIC will pull in DNS, mDNS, ARP, and every
  other device on the segment.

## Sanitization

Every pcap must pass this checklist before it is committed. Run the
commands from the repo root; substitute your pcap path.

### 1. No home-network or production IPs

The capture must contain only lab or loopback addresses. For the current
lab, the allowed IPs are `172.18.0.0/16` (Docker bridge) and `127.0.0.1`
(loopback). Any other IP is a red flag.

```bash
tshark -r <pcap> -T fields -e ip.src -e ip.dst 2>/dev/null | sort -u
```

Review every line. If you see `192.168.1.x`, `10.0.0.x`, a public IP, or
anything that is not a Docker bridge or loopback address, the capture is
contaminated. Recapture with a tighter BPF filter or editcap out the
offending flows.

### 2. No DNS, mDNS, LLMNR, or NBNS

Service discovery protocols broadcast hostnames and can reveal internal
infrastructure.

```bash
tshark -r <pcap> -Y "dns or nbns or llmnr" 2>/dev/null | wc -l
# Expected: 0
```

If non-zero, recapture with `and not dns and not nbns and not llmnr`
added to the BPF filter.

### 3. No credentials or tokens in HTTP payloads

Search the HTTP text for common secret patterns:

```bash
tshark -r <pcap> -Y "http" -T fields -e http.file_data 2>/dev/null \
  | grep -iE "password|secret|token|api[_-]?key|authorization|bearer" \
  | head -20
```

If anything matches, the capture contains credentials. Do not commit it.
Recapture against a lab that uses dummy values, or redact the payloads
with `editcap` + a custom filter.

### 4. No real hostnames or MAC addresses that identify a site

Check for hostnames in HTTP headers and Host fields:

```bash
tshark -r <pcap> -Y "http" -T fields -e http.host 2>/dev/null | sort -u
```

Lab hostnames like `localhost`, `127.0.0.1`, or container names are fine.
A real domain, an internal hostname (`fileserver01.corp.example`), or a
ISP-assigned name is not.

Check MAC addresses. Docker bridge MACs (`02:42:*`) are fine. A vendor
OUI that maps to a specific NIC model in a specific building is not.

```bash
tshark -r <pcap> -T fields -e eth.src -e eth.dst 2>/dev/null | sort -u
```

### 5. Verify the packet count matches the README

The README for each capture directory documents the expected packet count.
If it does not match, something changed between capture and commit.

```bash
tshark -r <pcap> 2>/dev/null | wc -l
```

## What belongs in a capture directory

Each capture gets its own directory under the repo root:

```
<lab-name>/
  README.md          # what was captured, how, tap points, verification
  <name>.pcap        # the capture(s)
  *.png              # screenshots (Wireshark, Teleseer, etc)
```

The README must include:

- Tap point(s) and why they were chosen
- BPF filter used at capture time
- Traffic generation commands (exact scripts and flags)
- Packet count and linktype
- Verification commands (the `tshark` filters that prove the capture
  is clean and complete)
- Credits for the vulnerability research and any tooling used

## What does not belong

- Raw captures from production or customer environments.
- Captures that include traffic to or from the internet (DNS to a real
  resolver, HTTP to a real CDN, etc).
- `.DS_Store`, editor swap files, or any OS cruft.
- Captures where the exploit was run against a target that is not a
  disposable lab container.

## Review process

1. Run the sanitization checklist above. Paste the output of each step
   into the PR description.
2. A maintainer reviews the IP list, protocol list, and HTTP text for
   anything the grep patterns above might miss.
3. Both pcaps (inside and outside, if applicable) must be in the same
   commit with matching README documentation.
