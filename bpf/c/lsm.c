#include <unistd.h>
#include "lsm.skel.h"

#define PIN_PATH "/sys/fs/bpf/lsm_fs"

int main(int argc, char **argv) {
	struct lsm_bpf *prog;
	int err = 0;

	prog = lsm_bpf__open_and_load();
	if (!prog)
		fprintf(stdout, "could not load bpf program");

	if (access(PIN_PATH, F_OK) == 0) {
		err = remove(PIN_PATH);
		if (err != 0) {
			fprintf(stdout, "could not remove old pin: %d", err);
			goto out;
		}
	}
	err = bpf_program__pin(prog->progs.open_audit,
			       PIN_PATH);
	if (err) {
		fprintf(stdout, "could not pin program: %d", err);
		goto out;
	}

	err = lsm_bpf__attach(prog);
	if (err) {
		fprintf(stdout, "could not attach program: %d", err);
		goto out;
	}

	/*
	 * After we finish sleeping and the userspace program quits,
	 * the BPF program doesn't get triggered anymore.
	 */
	sleep(30);

out:
	lsm_bpf__destroy(prog);
	return err;
}
