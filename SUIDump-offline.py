# SUIDump - SUID Privilege Escalation Checker
# Version: 1.02-offline
# Author: lypd0
# GitHub Repository: https://github.com/lypd0/SUIDump

import os
import argparse
import subprocess
import time

# List of SUID binary names
suid_binary_names = set([
    "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell", "atobm",
    "awk", "base32", "base64", "basenc", "basez", "bash", "bc", "bridge", "busybox", "bzip2", "cabal", "capsh",
    "cat", "chmod", "choom", "chown", "chroot", "clamscan", "cmp", "column", "comm", "cp", "cpio", "cpulimit",
    "csh", "csplit", "csvtool", "cupsfilter", "curl", "cut", "dash", "date", "dd", "debugfs", "dialog", "diff",
    "dig", "distcc", "dmsetup", "docker", "dosbox", "ed", "efax", "elvish", "emacs", "env", "eqn", "espeak",
    "expand", "expect", "file", "find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie",
    "genisoimage", "gimp", "grep", "gtester", "gzip", "hd", "head", "hexdump", "highlight", "hping3",
    "iconv", "install", "ionice", "ip", "ispell", "jjs", "join", "jq", "jrunscript", "julia", "ksh", "ksshell",
    "kubectl", "less", "logsave", "look", "lua", "make", "mawk", "more", "mosquitto", "msgattrib", "msgcat",
    "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime", "mv", "nasm", "nawk", "ncftp", "nft", "nice",
    "nl", "nm", "nmap", "node", "nohup", "od", "openssl", "openvpn", "pandoc", "paste", "perf", "perl",
    "pexec", "pg", "php", "pidstat", "pr", "ptx", "python", "rc", "readelf", "restic", "rev", "rlwrap",
    "rsync", "rtorrent", "run-parts", "rview", "rvim", "sash", "scanmem", "sed", "setarch", "setfacl",
    "setlock", "shuf", "soelim", "softlimit", "sort", "sqlite3", "ss", "ssh-agent", "ssh-keygen",
    "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings", "sysctl", "systemctl",
    "tac", "tail", "taskset", "tbl", "tclsh", "tee", "terraform", "tftp", "tic", "time", "timeout",
    "troff", "ul", "unexpand", "uniq", "unshare", "unsquashfs", "unzip", "update-alternatives", "uudecode",
    "uuencode", "vagrant", "view", "vigr", "vim", "vimdiff", "vipw", "w3m", "watch", "wc", "wget",
    "whiptail", "xargs", "xdotool", "xmodmap", "xmore", "xxd", "xz", "yash", "zsh", "zsoelim"
])

# Function to find SUID binaries
def find_suid_binaries():
    suid_binaries = []
    try:
        # Traverse the filesystem to find SUID binaries
        for root, _, files in os.walk('/'):
            for filename in files:
                filepath = os.path.join(root, filename)
                # Check if the file is executable and has the SUID bit set
                if os.access(filepath, os.X_OK) and os.stat(filepath).st_mode & 0o4000:
                    suid_binaries.append(filepath)
    except KeyboardInterrupt:
        print("\n\033[31m[-]\033[0m Scan interrupted by the user.")
        exit(1)
    except Exception as e:
        # Handle any exceptions that may occur during the search
        print(f"\033[31m[-]\033[0m Error while finding SUID binaries: {str(e)}")
    return suid_binaries

# Function to check SUID binaries against GTFOBins
def check_local_binary(binary_name, verbose=False, retries=3, retry_delay=5):
    try:
        if binary_name in suid_binary_names:
            print(f"\n\033[1;32m[+]\033[0m {binary_name} --> potential vector found")
            return True
        else:
            if verbose:
                print(f"\033[36m[*]\033[0m {binary_name} --> not vulnerable")
    except KeyboardInterrupt:
        print("\n\033[31m[-]\033[0m Scan interrupted by the user.")
        exit(1)
    except Exception as e:
        if retries > 0:
            # Handle retries
            print(f"\033[31m[-]\033[0m Error while checking {binary_name}, retrying...")
            time.sleep(retry_delay)
            check_local_binary(binary_name, verbose, retries - 1)
        else:
            print(f"\033[31m[-]\033[0m Error while checking {binary_name}")
    return False

# Main function
def main():
    print(" ")
    print("\033[1;36m  +\033[0m .-. . . .-. .-. . . .  . .-. \033[1;36m+ ")
    print("\033[1;36m + \033[0m `-. | |  |  |  )| | |\/| |-' \033[1;36m + ")   
    print("\033[1;36m  +\033[0m `-' `-' `-' `-' `-' '  ` '   \033[1;36m+ ")
    print("\033[36m       <\033[0m 1.02-o\033[36m @\033[0m lypd0.com\033[36m >\n\033[0m")
    print("")

    parser = argparse.ArgumentParser(description="SUID Privilege Escalation Checker")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print additional information during scan")
    args = parser.parse_args()

    print(f"\033[36m[~]\033[0m Collecting SUID files...")
    suid_binaries = find_suid_binaries()
    print(f"\033[36m[~]\033[0m Collected ({len(suid_binaries)}) SUID binaries.")
    print(f"\033[36m[~]\033[0m Scanning...")

    if not suid_binaries:
        print("\033[31m[-]\033[0m No SUID binaries found.")
        return

    for binary_path in suid_binaries:
        time.sleep(0.05)
        binary_name = os.path.basename(binary_path)
        if check_local_binary(binary_name, args.verbose):
            print("\033[34m    >\033[0m Potential\033[1;32m VULNERABLE\033[0m binary found")
            print(f"\033[34m    >\033[0m Location:\033[3;90m {binary_path}")
            print(f"\033[34m    >\033[0m Exploit:\033[3;90m https://gtfobins.github.io/gtfobins/{binary_name}#suid\n\033[0m")
            
    print("\033[36m[~]\033[0m Scan terminated.\n ")       

if __name__ == "__main__":
    main()
