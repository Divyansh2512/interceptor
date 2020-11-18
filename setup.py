import os
from os import system
import sys
import time


def has_root():
    return os.geteuid() == 0

if not has_root():
  print("[-] Please run as Root... Quitting!!")
  sys.exit(1)
else:
  print("[+] Running as Root")
  print("[+] Installing Dependencies....")
  time.sleep(2)
  system("apt-get update")
  system("apt-get install build-essential python-dev libnetfilter-queue-dev")
  system("pip3 install -r dependencies.txt")
