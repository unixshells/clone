#!/usr/bin/env python3
"""Debug incremental snapshot by sending control commands."""
import socket, struct, json, sys, time, os

def send_cmd(sock_path, cmd_dict):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(sock_path)
    payload = json.dumps(cmd_dict).encode()
    s.sendall(struct.pack('<I', len(payload)) + payload)
    hdr = b''
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            s.close()
            return None
        hdr += chunk
    resp_len = struct.unpack('<I', hdr)[0]
    resp = b''
    while len(resp) < resp_len:
        chunk = s.recv(resp_len - len(resp))
        if not chunk:
            break
        resp += chunk
    s.close()
    return resp.decode()

if len(sys.argv) < 2:
    print("Usage: debug_incr.py <vm_pid>")
    sys.exit(1)

pid = sys.argv[1]
sock = f"/tmp/clone-{pid}.sock"

print(f"Connecting to {sock}")

# Full snapshot
print("\n--- Full Snapshot ---")
resp = send_cmd(sock, {"cmd": "snapshot", "vm_id": "self", "output_path": "/tmp/dbg-full"})
print(f"Response: {resp}")

time.sleep(2)

# Incremental snapshot
print("\n--- Incremental Snapshot ---")
try:
    resp = send_cmd(sock, {"cmd": "incremental_snapshot", "output_path": "/tmp/dbg-incr", "base_template": "/tmp/dbg-full"})
    print(f"Response: {resp}")
except Exception as e:
    print(f"Error: {e}")

# Check files
for d in ["/tmp/dbg-full", "/tmp/dbg-incr"]:
    if os.path.isdir(d):
        files = os.listdir(d)
        sizes = {f: os.path.getsize(os.path.join(d, f)) for f in files}
        print(f"\n{d}: {sizes}")
    else:
        print(f"\n{d}: NOT FOUND")
