// SPDX-License-Identifier: GPL-2.0
// Tracepoint on sys_enter_openat: count file opens per PID per second.
// Emits a perf event when a PID exceeds fd_threshold opens/sec.
//
// Compile: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//            -I/usr/include/x86_64-linux-gnu \
//            -c fd_monitor.bpf.c -o fd_monitor.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NSEC_PER_SEC 1000000000ULL

struct fd_event {
    __u32 pid;
    __u32 open_rate; // opens per second
};

struct pid_fd_state {
    __u64 window_start;
    __u32 open_count;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct pid_fd_state);
} fd_counters SEC(".maps");

// Configurable threshold (opens/sec)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} fd_threshold SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} fd_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct pid_fd_state *state = bpf_map_lookup_elem(&fd_counters, &pid);
    if (!state) {
        struct pid_fd_state new_state = {
            .window_start = now,
            .open_count = 1,
        };
        bpf_map_update_elem(&fd_counters, &pid, &new_state, BPF_NOEXIST);
        return 0;
    }

    if ((now - state->window_start) >= NSEC_PER_SEC) {
        __u32 key = 0;
        __u32 *thresh = bpf_map_lookup_elem(&fd_threshold, &key);
        __u32 threshold = thresh ? *thresh : 100;

        if (state->open_count >= threshold) {
            struct fd_event ev = {
                .pid = pid,
                .open_rate = state->open_count,
            };
            bpf_perf_event_output(ctx, &fd_events, BPF_F_CURRENT_CPU,
                                  &ev, sizeof(ev));
        }
        // Reset window
        state->window_start = now;
        state->open_count = 1;
    } else {
        state->open_count++;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
