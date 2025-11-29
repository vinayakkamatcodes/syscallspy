#!/usr/bin/env python3
# final_spy.py
from bcc import BPF
from datetime import datetime
import sys

# ---------------------------------------------------------
# C CODE: The Kernel-side eBPF Program
# ---------------------------------------------------------
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event {
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event data = {};
    
    // 1. Get the process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 2. Get the filename
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# ---------------------------------------------------------
# PYTHON CODE: The User-space Controller
# ---------------------------------------------------------

# 1. Compile and Load
bpf = BPF(text=bpf_source)

# 2. Define the Handler
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    
    command = event.filename.decode('utf-8', 'ignore')
    comm_name = event.comm.decode('utf-8', 'ignore')
    
    if not command:
        command = comm_name

    # --- FILTER ---
    # Updated based on your logs to hide Docker noise
    ignore_list = [
        "code", "node", "chrome", "dockerd", "snap", 
        "cpuUsage.sh", "run-cups-browse", "sh", 
        "docker", "sysstat", "sa1"
    ]
    
    for word in ignore_list:
        if word in command:
            return

    # 3. Print
    ts = datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] EXEC: {command}", flush=True)

# 3. Main Loop
print("🚀 Syscall Spy: Monitoring execve()... Press Ctrl+C to exit")
print("-" * 60)

bpf["events"].open_perf_buffer(print_event)
try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n🛑 Stopped.")
    sys.exit(0)