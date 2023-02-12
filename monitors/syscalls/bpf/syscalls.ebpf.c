#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "syscount.h"
 #include "maps.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile bool filter_cg = false;
const volatile bool count_by_process = false;
const volatile bool measure_latency = false;
const volatile bool filter_failed = false;
const volatile int filter_errno = false;
const volatile pid_t filter_pid = 0;			//set to PID of monitor if you want to exclude these messages
const volatile pid_t monitor_pid = 0; 			//set to PID if you only want to monitor that particular process
const volatile bool filter_container_only = false; //set to true if you only want to monitor specified container pid namespaces
const volatile bool filter_monitor_events = false;

#define MAX_ENTRIES 512

#define TASK_COMM_LEN 16




struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} syscall_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} namespace_table SEC(".maps");

#define TASK_COMM_LEN 16

struct event_t {
    u64 cgroup_id; // cgroup id
    u32 host_tid;  // tid in host pid namespace
    u32 host_pid;  // pid in host pid namespace
    u32 host_ppid; // ppid in host pid namespace

    u32 tid;  // thread id in userspace
    u32 pid;  // process id in userspace
    u32 ppid; // parent process id in userspace
    u32 uid;
    u32 gid;

    u32 cgroup_ns_id;
    u32 ipc_ns_id;
    u32 net_ns_id;
    u32 mount_ns_id;
    u32 pid_ns_id;
    u32 time_ns_id;
    u32 user_ns_id;
    u32 uts_ns_id;

    char comm[TASK_COMM_LEN]; // the name of the executable (excluding the path)
};

//useful informagtion
//
// capturing trace output here:  sudo cat /sys/kernel/debug/tracing/trace_pipe
// useful link on disecting PIDs: https://github.com/mozillazg/hello-libbpfgo/blob/master/05-get-process-info/main.bpf.c
//
static __always_inline u32 get_namespace_id() {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct nsproxy *namespaceproxy = BPF_CORE_READ(task, nsproxy);
    return (u32) BPF_CORE_READ(namespaceproxy, pid_ns_for_children, ns.inum);
}



SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{

	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	u32 ps_ns_id = 0;

	//u32 pns_id = (u32) BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

	u64 *val, zero = 0;
	u32 key = args->id;
	struct start_t *val2;
	u64 one = 1;

	//DO SOME UP FRONT FILTERING
		//filter out when we get a -1 for a syscall, dont know why this happens but its documented
		//that sometimes ebpf returns -1 for a syscall identifier basically 0xFFFFFFFF
		if(key == (u32)-1)
			return 0;
		
		//Check for filters if we are not doing just containers
		if (!filter_container_only) {
			//filter a specific PID if enabled
			if ((filter_pid) && (filter_pid == pid)){
				//u32 nid = ns_id;
				//bpf_printk("filtering event for monitor %u", pid_ns_id );
				return 0;
			}
		} else  { //we are in container only mode, see if this is an event of interest 
			ps_ns_id = get_namespace_id();	//get namspace of current PID
			u32 *val;
			val = bpf_map_lookup_elem(&namespace_table, &ps_ns_id);
			if (!val || *val == 0)
				return 0;
		}

		//handle filtering out of the monitor syscalls if enabled
		if((monitor_pid) && (monitor_pid != pid))
			return 0;
	//END OF FILTERING

	//we have an event of interest, so add it to the syscall hashmap
	val = bpf_map_lookup_or_try_init(&syscall_table, &key, &zero);
	
	if (val) {
		__sync_fetch_and_add(val,one);
	}
	
	return 0;
}
