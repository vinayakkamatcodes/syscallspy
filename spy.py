#!/usr/bin/env python3
# spy.py
from bcc import BPF
from datetime import datetime
import sys

# Load BPF program
bpf_code = open('spy.c', 'r').read()
bpf = BPF(text=bpf_code)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("execve"), fn_name="trace_execve")

# Callback for events
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    ts = datetime.fromtimestamp(event.timestamp / 1e9).strftime('%H:%M:%S')
    print(f"[{ts}] EXEC: {event.comm.decode('utf-8', 'ignore')}")

# Print header
print("🚀 Syscall Spy: Monitoring execve()... Press Ctrl+C to exit")
print("-" * 60)

# Start polling
bpf["events"].open_perf_buffer(print_event)
try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n🛑 Stopped.")
    sys.exit(0)