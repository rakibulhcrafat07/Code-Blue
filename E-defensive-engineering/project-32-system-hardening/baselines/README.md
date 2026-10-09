# Baselines & exports

This folder holds the baseline/scoring artefacts a hardening project produces.
(Place your real exports here when you run the tools.)

- `cis-cat-windows-before.html` / `-after.html` — CIS-CAT Lite reports (Windows member server, CIS L1)
- `lynis-linux-before.log` / `-after.log` — Lynis audit output (Ubuntu/RHEL)
- `hardening-GPO.zip` — exported hardening GPO (Backup-GPO) for the Windows baseline
- `wazuh-sca-policy.yml` — Wazuh SCA policy used to monitor drift

## Commands used

### Windows (CIS-CAT Lite + GPO)
```powershell
# Baseline score
.\CIS-CAT.exe -b benchmarks\CIS_Microsoft_Windows_Server_2022_Benchmark.xml -l 1 -r reports
# Apply via GPO (example settings)
# - min password length 14, complexity on, lockout 10/15
# - Turn Off Multicast Name Resolution (LLMNR)
# - NetBIOS over TCP/IP = Disabled (DHCP opt 001/002 or per-NIC)
# - Network security: LAN Manager auth level = Send NTLMv2 only, refuse LM & NTLM
Backup-GPO -Name "CIS-L1-Hardening" -Path .\hardening-GPO
# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### Linux (Lynis)
```bash
lynis audit system            # before -> note the hardening index
# apply CIS L1 (pam pwquality, login.defs, sshd_config, grub, auditd, nftables)
lynis audit system            # after -> re-check the index
```

### Drift monitoring (Wazuh SCA)
```xml
<!-- ossec.conf: enable SCA with the CIS policy -->
<sca><enabled>yes</enabled><policies>
  <policy>cis_win2022_L1.yml</policy>
  <policy>cis_ubuntu22_L1.yml</policy>
</policies></sca>
```
