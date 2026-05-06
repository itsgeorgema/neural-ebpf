// SPDX-License-Identifier: GPL-2.0
// Tracepoint on sched_switch: track per-PID CPU time and emit perf events
// when a process exceeds the configured threshold.
//
// Compile: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//            -I/usr/include/x86_64-linux-gnu \
//            -c cpu_monitor.bpf.c -o cpu_monitor.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NSEC_PER_SEC 1000000000ULL
// Window over which we accumulate CPU time (100ms)
#define WINDOW_NS    100000000ULL

struct cpu_event {
    __u32 pid;
    __u32 cpu;
    __u64 duration_ns; // CPU time in this window
};

// Per-PID: timestamp when this PID was last scheduled ON
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} start_times SEC(".maps");

// Per-PID: accumulated CPU ns in current window
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} cpu_accum SEC(".maps");

// Per-PID: start of current measurement window
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} window_start SEC(".maps");

// Configurable CPU threshold (ns of CPU per WINDOW_NS). 0 = key not set.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cpu_threshold SEC(".maps");

// Perf ring buffer for userspace consumption
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    // --- Process going OFF cpu (prev) ---
    __u32 prev_pid = BPF_CORE_READ(ctx, prev_pid);
    if (prev_pid != 0) {
        __u64 *start = bpf_map_lookup_elem(&start_times, &prev_pid);
        if (start) {
            __u64 delta = now - *start;
            __u64 *accum = bpf_map_lookup_elem(&cpu_accum, &prev_pid);
            __u64 new_accum = accum ? (*accum + delta) : delta;

            __u64 *win = bpf_map_lookup_elem(&window_start, &prev_pid);
            __u64 win_start = win ? *win : now;

            if ((now - win_start) >= WINDOW_NS) {
                // Evaluate threshold
                __u32 key = 0;
                __u64 *thresh = bpf_map_lookup_elem(&cpu_threshold, &key);
                __u64 threshold = thresh ? *thresh : (WINDOW_NS * 80 / 100);

                if (new_accum >= threshold) {
                    struct cpu_event ev = {
                        .pid = prev_pid,
                        .cpu = bpf_get_smp_processor_id(),
                        .duration_ns = new_accum,
                    };
                    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                         &ev, sizeof(ev));
                }
                // Reset window
                bpf_map_update_elem(&window_start, &prev_pid, &now, BPF_ANY);
                __u64 zero = 0;
                bpf_map_update_elem(&cpu_accum, &prev_pid, &zero, BPF_ANY);
            } else {
                bpf_map_update_elem(&cpu_accum, &prev_pid, &new_accum, BPF_ANY);
            }
            bpf_map_delete_elem(&start_times, &prev_pid);
        }
    }

    // --- Process going ON cpu (next) ---
    __u32 next_pid = BPF_CORE_READ(ctx, next_pid);
    if (next_pid != 0) {
        bpf_map_update_elem(&start_times, &next_pid, &now, BPF_ANY);

        // Initialize window if not set
        if (!bpf_map_lookup_elem(&window_start, &next_pid)) {
            bpf_map_update_elem(&window_start, &next_pid, &now, BPF_ANY);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
