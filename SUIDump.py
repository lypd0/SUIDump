# SUIDump - SUID Privilege Escalation Checker
# Version: 1.02
# Author: lypd0
# GitHub Repository: https://github.com/lypd0/SUIDump

import os
import argparse
import subprocess
import time

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
def check_gtfobins(binary_name, verbose=False, retries=3, retry_delay=5):
    url = f"https://gtfobins.github.io/gtfobins/{binary_name}/"
    
    try:
        # Send an HTTP request to GTFOBins and check for privilege escalation vectors
        response = subprocess.check_output(["curl", "-s", "-A", "Mozilla/5.0", url], stderr=subprocess.DEVNULL).decode("utf-8")

        if "#suid" in response:
            print(f"\n\033[1;32m[+]\033[0m {binary_name} --> potential vector found")
            return True
        else:
            if verbose:
                print(f"\033[35m[*]\033[0m {binary_name} --> not vulnerable")
    except KeyboardInterrupt:
        print("\n\033[31m[-]\033[0m Scan interrupted by the user.")
        exit(1)
    except Exception as e:
        if retries > 0:
            # Handle rate limiting issues and retry with a delay
            print(f"\033[31m[-]\033[0m Error while checking {binary_name} (possibly rate limited), retrying...")
            time.sleep(retry_delay)
            check_gtfobins(binary_name, verbose, retries - 1)
        else:
            print(f"\033[31m[-]\033[0m Error while checking {binary_name} (rate limited, no more retries).")
    return False

# Main function
def main():
    print(" ")
    print("\033[1;35m  +\033[0m .-. . . .-. .-. . . .  . .-. \033[1;35m+ ")
    print("\033[1;35m + \033[0m `-. | |  |  |  )| | |\/| |-' \033[1;35m + ")   
    print("\033[1;35m  +\033[0m `-' `-' `-' `-' `-' '  ` '   \033[1;35m+ ")
    print("\033[35m        <\033[0m 1.02\033[35m @\033[0m lypd0.com\033[35m >     \n\033[0m")

    parser = argparse.ArgumentParser(description="SUID Privilege Escalation Checker")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print additional information during scan")
    args = parser.parse_args()

    print(f"\033[35m[~]\033[0m Collecting SUID files...")
    suid_binaries = find_suid_binaries()
    print(f"\033[35m[~]\033[0m Collected ({len(suid_binaries)}) SUID binaries.")
    print(f"\033[35m[~]\033[0m Scanning...")

    if not suid_binaries:
        print("\033[31m[-]\033[0m No SUID binaries found.")
        return

    for binary_path in suid_binaries:
        binary_name = os.path.basename(binary_path)
        if check_gtfobins(binary_name, args.verbose):
            print("\033[34m    >\033[0m Potential\033[1;32m VULNERABLE\033[0m binary found")
            print(f"\033[34m    >\033[0m Location:\033[3;90m {binary_path}")
            print(f"\033[34m    >\033[0m Exploit:\033[3;90m https://gtfobins.github.io/gtfobins/{binary_name}#suid\n\033[0m")
            
    print("\033[35m[~]\033[0m Scan terminated.\n ")       

if __name__ == "__main__":
    main()
