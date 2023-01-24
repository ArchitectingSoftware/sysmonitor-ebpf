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
const volatile bool filter_monitor_events = false;

#define MAX_ENTRIES 512

#define TASK_COMM_LEN 16




struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} syscall_table SEC(".maps");


SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
	//bpf_printk("Filter MPID= %d, MonitorPID=%d", filter_pid, filter_pid);
	//bpf_trace_printk("debug - in sys_exit %d\n", 0);
	
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	u64 *val, zero = 0;
	u32 key = args->id;
	struct start_t *val2;
	u64 one = 1;

	//DO SOME UP FRONT FILTERING
		//filter out when we get a -1 for a syscall, dont know why this happens but its documented
		//that sometimes ebpf returns -1 for a syscall identifier basically 0xFFFFFFFF
		if(key == (u32)-1)
			return 0;
		//filter out a pid - for example dont capture syscalls from the monitor
		if ((filter_pid) && (filter_pid == pid))
			return 0;
		//if we want to monior only one pid, monitor pid must be current pid
		if((monitor_pid) && (monitor_pid != pid))
			return 0;
	//END OF FILTERING

	val = bpf_map_lookup_or_try_init(&syscall_table, &key, &zero);
	
	if (val) {
		__sync_fetch_and_add(val,one);
	}
	

	return 0;
}
