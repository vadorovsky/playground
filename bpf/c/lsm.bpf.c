#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("lsm/file_open")
int BPF_PROG(open_audit, struct file *file, int ret)
{
	bpf_printk("lsm/file_open event\n");
	bpf_printk("mode: %d\n", file->f_mode);
	bpf_printk("name: %s\n", file->f_path.dentry->d_name.name);

	if (ret != 0)
		return ret;

	return 0;
}

char __license[] SEC("license") = "GPL";
