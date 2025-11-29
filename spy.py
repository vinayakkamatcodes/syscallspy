#!/usr/bin/env python3
# spy.py
from bcc import BPF
from datetime import datetime
import sys

# 1. Load the BPF program
bpf_code = open('spy.c', 'r').read()
bpf = BPF(text=bpf_code)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("execve"), fn_name="trace_execve")

# 2. Define the Callback
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    
    # Get the filename (e.g., "/usr/bin/ls")
    command = event.argv.decode('utf-8', 'ignore')
    
    # Fallback to process name if filename is empty
    if not command:
        command = event.comm.decode('utf-8', 'ignore')

    # --- AGGRESSIVE FILTER ---
    # Ignore HP Laptop background scripts and standard noise
    ignore_list = [
        "code", "node", "chrome", "dockerd", "snap", 
        "cpuUsage.sh", "run-cups-browse", "sh", "bash"
    ]
    
    # If the command contains any word from the ignore list, skip it
    for ignore_word in ignore_list:
        if ignore_word in command:
            return

    # 3. Print the Result
    ts = datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] EXEC: {command}", flush=True)

# 4. Main Loop
print("🚀 Syscall Spy: Monitoring execve()... Press Ctrl+C to exit")
print("-" * 60)

bpf["events"].open_perf_buffer(print_event)
try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n🛑 Stopped.")
    sys.exit(0)