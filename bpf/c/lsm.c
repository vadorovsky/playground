#include <unistd.h>
#include "lsm.skel.h"

#define PIN_PATH "/sys/fs/bpf/lsm_fs"
#define PIN_LINK_PATH "/sys/fs/bpf/lsm_fs_link"

int remove_file_if_exists(const char *path)
{
	int err = 0;

	if (access(path, F_OK) == 0) {
		err = remove(path);
		if (err != 0) {
			fprintf(stdout, "could not remove old pin: %d", err);
			return err;
		}
	}

	return err;
}

int main(int argc, char **argv)
{
	struct lsm_bpf *prog;
	int err = 0;

	prog = lsm_bpf__open_and_load();
	if (!prog)
		fprintf(stdout, "could not load bpf program");


	if (remove_file_if_exists(PIN_PATH))
		goto out;
	if (remove_file_if_exists(PIN_LINK_PATH))
		goto out;

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

	err = bpf_link__pin(prog->links.open_audit,
			    PIN_LINK_PATH);
	if (err) {
		fprintf(stdout, "could not attach link: %d", err);
		goto out;
	}

out:
	lsm_bpf__destroy(prog);
	return err;
}
