// // ===== Dummy definitions for editor/linter (ignored by BCC) =====
// #ifndef BPF_PERF_OUTPUT
// #define BPF_PERF_OUTPUT(name) static void *name = 0;
// #endif

// #ifndef bpf_get_current_comm
// #define bpf_get_current_comm(buf, size) do {} while(0)
// #endif

// #ifndef bpf_ktime_get_ns
// #define bpf_ktime_get_ns() 0ULL
// #endif

// #ifndef bpf_probe_read_user_str
// #define bpf_probe_read_user_str(dst, sz, src) 0
// #endif

// #ifndef PT_REGS_PARM1
// #define PT_REGS_PARM1(x) ((x)->di)
// #endif
// // ================================================================
#include <linux/sched.h> // for task_struct

// Defining a data structure to send to userspace 

struct event{
    char comm[16];
    char argv[128];
    u64    timestamp;
};

// eBPF map to pass to user space
BPF_PERF_OUTPUT(events);

// Attach to execve syscall entry
int trace_execve(struct pt_regs *ctx){
    struct event data = {};
    data.timestamp = bpf_ktime_get_ns();

    // Get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Note: Full argv access is complex in eBPF.
    // We'll just note that execve happened (you can extend later!)
    bpf_probe_read_user_str(&data.argv, sizeof(data.argv), (void *)PT_REGS_PARM1(ctx));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}