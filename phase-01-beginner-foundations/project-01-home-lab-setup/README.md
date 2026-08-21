# Project 1 — Home Lab Setup

**Phase:** [1 — Beginner Foundations](../)
**Status:** ⬜ To Do

## Objective

Build the isolated virtual lab that every later phase in this roadmap runs on top of.

## Tasks

- [ ] Install a hypervisor (VirtualBox or VMware Workstation Player)
- [ ] Create a Windows 10/11 VM (evaluation ISO) — this becomes the "victim/monitored" host
- [ ] Create a Linux VM (Ubuntu Server or Kali) — this becomes the attacker/tools box
- [ ] Configure a host-only or internal network so both VMs can talk to each other but **not** to the internet unless explicitly needed
- [ ] Take a clean snapshot of both VMs before doing anything else, so the lab can always be reset
- [ ] Verify connectivity: ping between VMs, confirm no unintended internet access

## Tools

VirtualBox / VMware Workstation Player, Windows evaluation ISO, Ubuntu Server / Kali Linux ISO

## Deliverable

- Screenshot of both VMs running with confirmed host-only network connectivity
- Short write-up: network diagram (even hand-drawn/exported from draw.io) showing the lab topology, IP ranges used, and snapshot names

## Notes / Write-up

_(Fill in as you go — screenshots, gotchas, what you'd do differently.)_
