
![Logo](https://cdn.lypd0.com/SUIDump/logo.png)



<h1 align="center">SUIDump - Automatic SUID Checker</h1>
<p align="center">
  <a href="#"><img alt="forksBDG" src="https://img.shields.io/github/forks/lypd0/SUIDump.svg?style=for-the-badge"></a>
  <a href="#"><img alt="starsBDG" src="https://img.shields.io/github/stars/lypd0/SUIDump.svg?style=for-the-badge"></a>
  <a href="#"><img alt="licenseBDG" src="https://img.shields.io/github/license/lypd0/SUIDump.svg?style=for-the-badge"></a>
  <a href="#"><img alt="languageBDG" src="https://img.shields.io/badge/LANGUAGE-PYTHON-yellow?style=for-the-badge"></a>
<h3 align="center">Usage on unauthorized servers is strictly forbidden</h3>

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

or by using the following download&execute oneliner for dynamical deployment:

```bash
  curl https://cdn.lypd0.com/suidump > SUIDump.py && python3 SUIDump.py
```

using custom domain to avoid token limitations, feel free to replace URL with github raw.

## Contributions
Contributions, bug reports, and feature requests are welcome! Feel free to open an issue or submit a pull request.


## Credits
SUIDump acknowledges and expresses gratitude to the [GTFOBins project](https://gtfobins.github.io) for providing a valuable resource that makes privilege escalation vector identification more accessible.


### License
This project is licensed under the [MIT License](https://choosealicense.com/licenses/mit/). Please review the LICENSE file for more details.
