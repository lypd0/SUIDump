
![Logo](https://cdn.lypd0.com/SUIDump/logo.png)



<h1 align="center">SUIDump - Automatic SUID Checker</h1>
<p align="center">
  <a href="#"><img alt="forksBDG" src="https://img.shields.io/github/forks/lypd0/SUIDump?style=for-the-badge"></a>
  <a href="#"><img alt="starsBDG" src="https://img.shields.io/github/stars/lypd0/SUIDump?style=for-the-badge"></a>
  <a href="#"><img alt="licenseBDG" src="https://img.shields.io/github/license/lypd0/SUIDump?style=for-the-badge"></a>
  <a href="#"><img alt="languageBDG" src="https://img.shields.io/badge/LANGUAGE-PYTHON-yellow?style=for-the-badge"></a>
<h3 align="center">Usage on unauthorized systems is strictly forbidden</h3>

<p align="center"><img src="https://cdn.lypd0.com/SUIDump/demo.svg" alt="DEMO"></p>

# Overview

SUIDump is a Python script designed to help identify potential privilege escalation vectors in Linux systems by analyzing setuid (SUID) binaries. SUID binaries are executable programs that run with the privileges of the file owner, potentially allowing unauthorized users to escalate their privileges.

This tool automates the process of:

* Discovering SUID binaries on the system.
* Checking each SUID binary for known privilege escalation vectors using [GTFOBins](https://gtfobins.github.io), a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.
  
SUIDump provides a convenient way to assess the security of a Linux system and identify binaries that may pose a security risk. It offers both standard and verbose scanning modes, making it suitable for both quick assessments and in-depth security audits.


## Features
 * Automated discovery of SUID binaries on the system.
 * Integration with GTFOBins for identifying potential privilege escalation vectors.
 * Customizable scanning options, including verbose mode.
 * Rate limiting handling for checking GTFOBins (retries with a delay).
 * User-friendly command-line interface.


## Installation

Install SUIDump by using git

```bash
git clone https://github.com/lypd0/SUIDump && cd SUIDump && python3 SUIDump.py -h
```


## Deployment

Deploy SUIDump by running the script using python3:

```bash
python3 SUIDump.py -h
```

or by using the following download&execute oneliner for dynamical deployment (using custom domain to avoid token limitations, feel free to replace URL with github raw):

```bash
curl https://cdn.lypd0.com/suidump | python3 
```

<!-- (OFFLINE VERSION COMING SOON)
offline oneliner (no download or internet connection required, for CTFs)</br>
⚠️ this command will clear the console and its previous text before execution to avoid environment lag issues
```bash
clear && echo "IyBTVUlEdW1wIC0gU1VJRCBQcml2aWxlZ2UgRXNjYWxhdGlvbiBDaGVja2VyCiMgVmVyc2lvbjogMS4wMQojIEF1dGhvcjogbHlwZDAKIyBHaXRIdWIgUmVwb3NpdG9yeTogaHR0cHM6Ly9naXRodWIuY29tL2x5cGQwL1NVSUR1bXAKCmltcG9ydCBvcwppbXBvcnQgYXJncGFyc2UKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IHRpbWUKCiMgRnVuY3Rpb24gdG8gZmluZCBTVUlEIGJpbmFyaWVzCmRlZiBmaW5kX3N1aWRfYmluYXJpZXMoKToKICAgIHN1aWRfYmluYXJpZXMgPSBbXQogICAgdHJ5OgogICAgICAgICMgVHJhdmVyc2UgdGhlIGZpbGVzeXN0ZW0gdG8gZmluZCBTVUlEIGJpbmFyaWVzCiAgICAgICAgZm9yIHJvb3QsIF8sIGZpbGVzIGluIG9zLndhbGsoJy8nKToKICAgICAgICAgICAgZm9yIGZpbGVuYW1lIGluIGZpbGVzOgogICAgICAgICAgICAgICAgZmlsZXBhdGggPSBvcy5wYXRoLmpvaW4ocm9vdCwgZmlsZW5hbWUpCiAgICAgICAgICAgICAgICAjIENoZWNrIGlmIHRoZSBmaWxlIGlzIGV4ZWN1dGFibGUgYW5kIGhhcyB0aGUgU1VJRCBiaXQgc2V0CiAgICAgICAgICAgICAgICBpZiBvcy5hY2Nlc3MoZmlsZXBhdGgsIG9zLlhfT0spIGFuZCBvcy5zdGF0KGZpbGVwYXRoKS5zdF9tb2RlICYgMG80MDAwOgogICAgICAgICAgICAgICAgICAgIHN1aWRfYmluYXJpZXMuYXBwZW5kKGZpbGVwYXRoKQogICAgZXhjZXB0IEtleWJvYXJkSW50ZXJydXB0OgogICAgICAgIHByaW50KCJcblwwMzNbMzFtWy1dXDAzM1swbSBTY2FuIGludGVycnVwdGVkIGJ5IHRoZSB1c2VyLiIpCiAgICAgICAgZXhpdCgxKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICMgSGFuZGxlIGFueSBleGNlcHRpb25zIHRoYXQgbWF5IG9jY3VyIGR1cmluZyB0aGUgc2VhcmNoCiAgICAgICAgcHJpbnQoZiJcMDMzWzMxbVstXVwwMzNbMG0gRXJyb3Igd2hpbGUgZmluZGluZyBTVUlEIGJpbmFyaWVzOiB7c3RyKGUpfSIpCiAgICByZXR1cm4gc3VpZF9iaW5hcmllcwoKIyBGdW5jdGlvbiB0byBjaGVjayBTVUlEIGJpbmFyaWVzIGFnYWluc3QgR1RGT0JpbnMKZGVmIGNoZWNrX2d0Zm9iaW5zKGJpbmFyeV9uYW1lLCB2ZXJib3NlPUZhbHNlLCByZXRyaWVzPTMsIHJldHJ5X2RlbGF5PTUpOgogICAgdXJsID0gZiJodHRwczovL2d0Zm9iaW5zLmdpdGh1Yi5pby9ndGZvYmlucy97YmluYXJ5X25hbWV9LyIKICAgIAogICAgdHJ5OgogICAgICAgICMgU2VuZCBhbiBIVFRQIHJlcXVlc3QgdG8gR1RGT0JpbnMgYW5kIGNoZWNrIGZvciBwcml2aWxlZ2UgZXNjYWxhdGlvbiB2ZWN0b3JzCiAgICAgICAgcmVzcG9uc2UgPSBzdWJwcm9jZXNzLmNoZWNrX291dHB1dChbImN1cmwiLCAiLXMiLCAiLUEiLCAiTW96aWxsYS81LjAiLCB1cmxdLCBzdGRlcnI9c3VicHJvY2Vzcy5ERVZOVUxMKS5kZWNvZGUoInV0Zi04IikKCiAgICAgICAgaWYgIiNzdWlkIiBpbiByZXNwb25zZToKICAgICAgICAgICAgcHJpbnQoZiJcblwwMzNbMTszMm1bK11cMDMzWzBtIHtiaW5hcnlfbmFtZX0gLS0+IHBvdGVudGlhbCB2ZWN0b3IgZm91bmQiKQogICAgICAgICAgICByZXR1cm4gVHJ1ZQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIGlmIHZlcmJvc2U6CiAgICAgICAgICAgICAgICBwcmludChmIlwwMzNbMzVtWypdXDAzM1swbSB7YmluYXJ5X25hbWV9IC0tPiBub3QgdnVsbmVyYWJsZSIpCiAgICBleGNlcHQgS2V5Ym9hcmRJbnRlcnJ1cHQ6CiAgICAgICAgcHJpbnQoIlxuXDAzM1szMW1bLV1cMDMzWzBtIFNjYW4gaW50ZXJydXB0ZWQgYnkgdGhlIHVzZXIuIikKICAgICAgICBleGl0KDEpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgaWYgcmV0cmllcyA+IDA6CiAgICAgICAgICAgICMgSGFuZGxlIHJhdGUgbGltaXRpbmcgaXNzdWVzIGFuZCByZXRyeSB3aXRoIGEgZGVsYXkKICAgICAgICAgICAgcHJpbnQoZiJcMDMzWzMxbVstXVwwMzNbMG0gRXJyb3Igd2hpbGUgY2hlY2tpbmcge2JpbmFyeV9uYW1lfSAocG9zc2libHkgcmF0ZSBsaW1pdGVkKSwgcmV0cnlpbmcuLi4iKQogICAgICAgICAgICB0aW1lLnNsZWVwKHJldHJ5X2RlbGF5KQogICAgICAgICAgICBjaGVja19ndGZvYmlucyhiaW5hcnlfbmFtZSwgdmVyYm9zZSwgcmV0cmllcyAtIDEpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcHJpbnQoZiJcMDMzWzMxbVstXVwwMzNbMG0gRXJyb3Igd2hpbGUgY2hlY2tpbmcge2JpbmFyeV9uYW1lfSAocmF0ZSBsaW1pdGVkLCBubyBtb3JlIHJldHJpZXMpLiIpCiAgICByZXR1cm4gRmFsc2UKCiMgTWFpbiBmdW5jdGlvbgpkZWYgbWFpbigpOgogICAgcHJpbnQoIiAiKQogICAgcHJpbnQoIlwwMzNbMTszNW0gICtcMDMzWzBtIC4tLiAuIC4gLi0uIC4tLiAuIC4gLiAgLiAuLS4gXDAzM1sxOzM1bSsgIikKICAgIHByaW50KCJcMDMzWzE7MzVtICsgXDAzM1swbSBgLS4gfCB8ICB8ICB8ICApfCB8IHxcL3wgfC0nIFwwMzNbMTszNW0gKyAiKSAgIAogICAgcHJpbnQoIlwwMzNbMTszNW0gICtcMDMzWzBtIGAtJyBgLScgYC0nIGAtJyBgLScgJyAgYCAnICAgXDAzM1sxOzM1bSsgIikKICAgIHByaW50KCJcMDMzWzM1bSAgICAgICAgPFwwMzNbMG0gMS4wMlwwMzNbMzVtIEBcMDMzWzBtIGx5cGQwLmNvbVwwMzNbMzVtID4gICAgIFxuXDAzM1swbSIpCgogICAgcGFyc2VyID0gYXJncGFyc2UuQXJndW1lbnRQYXJzZXIoZGVzY3JpcHRpb249IlNVSUQgUHJpdmlsZWdlIEVzY2FsYXRpb24gQ2hlY2tlciIpCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCItdiIsICItLXZlcmJvc2UiLCBhY3Rpb249InN0b3JlX3RydWUiLCBoZWxwPSJQcmludCBhZGRpdGlvbmFsIGluZm9ybWF0aW9uIGR1cmluZyBzY2FuIikKICAgIGFyZ3MgPSBwYXJzZXIucGFyc2VfYXJncygpCgogICAgcHJpbnQoZiJcMDMzWzM1bVt+XVwwMzNbMG0gQ29sbGVjdGluZyBTVUlEIGZpbGVzLi4uIikKICAgIHN1aWRfYmluYXJpZXMgPSBmaW5kX3N1aWRfYmluYXJpZXMoKQogICAgcHJpbnQoZiJcMDMzWzM1bVt+XVwwMzNbMG0gQ29sbGVjdGVkICh7bGVuKHN1aWRfYmluYXJpZXMpfSkgU1VJRCBiaW5hcmllcy4iKQogICAgcHJpbnQoZiJcMDMzWzM1bVt+XVwwMzNbMG0gU2Nhbm5pbmcuLi4iKQoKICAgIGlmIG5vdCBzdWlkX2JpbmFyaWVzOgogICAgICAgIHByaW50KCJcMDMzWzMxbVstXVwwMzNbMG0gTm8gU1VJRCBiaW5hcmllcyBmb3VuZC4iKQogICAgICAgIHJldHVybgoKICAgIGZvciBiaW5hcnlfcGF0aCBpbiBzdWlkX2JpbmFyaWVzOgogICAgICAgIGJpbmFyeV9uYW1lID0gb3MucGF0aC5iYXNlbmFtZShiaW5hcnlfcGF0aCkKICAgICAgICBpZiBjaGVja19ndGZvYmlucyhiaW5hcnlfbmFtZSwgYXJncy52ZXJib3NlKToKICAgICAgICAgICAgcHJpbnQoIlwwMzNbMzRtICAgID5cMDMzWzBtIFBvdGVudGlhbFwwMzNbMTszMm0gVlVMTkVSQUJMRVwwMzNbMG0gYmluYXJ5IGZvdW5kIikKICAgICAgICAgICAgcHJpbnQoZiJcMDMzWzM0bSAgICA+XDAzM1swbSBMb2NhdGlvbjpcMDMzWzM7OTBtIHtiaW5hcnlfcGF0aH0iKQogICAgICAgICAgICBwcmludChmIlwwMzNbMzRtICAgID5cMDMzWzBtIEV4cGxvaXQ6XDAzM1szOzkwbSBodHRwczovL2d0Zm9iaW5zLmdpdGh1Yi5pby9ndGZvYmlucy97YmluYXJ5X25hbWV9I3N1aWRcblwwMzNbMG0iKQogICAgICAgICAgICAKICAgIHByaW50KCJcMDMzWzM1bVt+XVwwMzNbMG0gU2NhbiB0ZXJtaW5hdGVkLlxuICIpICAgICAgIAoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIG1haW4oKQ==" | base64 -d | python3
```
-->

## Contributions
Contributions, bug reports, and feature requests are welcome! Feel free to open an issue or submit a pull request.


## Credits
SUIDump acknowledges and expresses gratitude to the [GTFOBins project](https://gtfobins.github.io) for providing a valuable resource that makes privilege escalation vector identification more accessible.


### License
This project is licensed under the [MIT License](https://choosealicense.com/licenses/mit/). Please review the LICENSE file for more details.
