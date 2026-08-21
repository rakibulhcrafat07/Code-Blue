# Project 4 — DNS & HTTP Deep-Dive Lab

**Phase:** [2 — Networking Deep Dive](../)
**Status:** ⬜ To Do

## Objective

Most detections start with DNS or HTTP. Get precise about what normal traffic looks like at that layer.

## Tasks

- [ ] Capture DNS traffic while browsing normally; identify query types (A, AAAA, MX, TXT)
- [ ] Capture an HTTP (not HTTPS) session and read the full request/response in Wireshark
- [ ] Capture a TLS handshake and identify the SNI field (even though the payload is encrypted)
- [ ] Simulate one "suspicious" DNS pattern — e.g., a script doing rapid, repeated lookups to random-looking subdomains — and capture it
- [ ] Note what would make that pattern detectable in a SIEM later (Phase 4)

## Tools

Wireshark, a lab VM, a simple script to generate the DNS pattern

## Deliverable

A short write-up comparing "normal" DNS/HTTP traffic to the simulated suspicious pattern, with annotated packet captures.

## Notes / Write-up

_(Fill in as you go.)_
