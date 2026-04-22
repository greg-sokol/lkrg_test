// SPDX-License-Identifier: GPL-2.0 OR MIT
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kprobes.h>

#ifndef CONFIG_X86
#error "Sorry, only X86 is currently supported"
#endif

#include <asm/msr.h>
#define LKRG_TEST_PROCFS_PATH "lkrg_test"
#define LKRG_TEST_MAX_CMD 128

#define MSR MSR_SYSCALL_MASK
#define REGNAME "MSR_SYSCALL_MASK"
#define FLIP X86_EFLAGS_FIXED

static struct proc_dir_entry *lkrg_test_proc;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_ptr;

typedef void *(*text_poke_t)(void *addr, const void *opcode, size_t len);
static text_poke_t text_poke_ptr;

/* kallsyms's been unexported for quite a while */
/* Use the kprobe trick */
static int __init resolve_kallsyms_lookup_name(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("lkrg_test: register_kprobe() failed: %d\n", ret);
		return ret;
	}
	kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	if (!kallsyms_lookup_name_ptr) {
		pr_err("lkrg_test: kallsyms_lookup_name addr came back NULL\n");
		return -ENOENT;
	}
	return 0;
}

static int lkrg_test_contaminate_init(void)
{
	int ret = resolve_kallsyms_lookup_name();
	if (ret) {
		pr_err("lkrg_test: resolve_kallsyms_lookup_name() failed: %d\n",
		       ret);
		return ret;
	}
	// TODO: In case of ARM this will have to use patch_text
	if (!text_poke_ptr) {
		text_poke_ptr =
			(text_poke_t)kallsyms_lookup_name_ptr("text_poke");
		if (!text_poke_ptr) {
			pr_err("lkrg_test: cannot resolve text_poke\n");
			return -ENOENT;
		}
	}
	return 0;
}

static int lkrg_test_contaminate_text(unsigned long addr)
{
	void *ret = NULL;
	u32 pattern = 0xdeadbeef;

	pr_info("lkrg_test: poking 0x%08x at addr %px\n", pattern,
		(void *)addr);

	ret = text_poke_ptr((void *)ALIGN((addr + 16), sizeof(u32)), &pattern, sizeof(pattern));
	if (!ret) {
		pr_err("lkrg_test: text_poke returned NULL\n");
		return -EFAULT;
	}
	return 0;
}

static int lkrg_test_contaminate_kernel_core(void)
{
	int ret = 0;
	static const char * const contaminate_sym_name = "kgdb_arch_init";
	unsigned long addr = kallsyms_lookup_name_ptr(contaminate_sym_name);
	if (!addr) {
		pr_err("lkrg_test: cannot resolve %s\n", contaminate_sym_name);
		return -ENOENT;
	}
	pr_info("lkrg_test: resolved  %s to 0x%08lx\n", contaminate_sym_name,  addr);
	ret = lkrg_test_contaminate_text(addr);
	if (ret) {
		pr_err("lkrg_test: lkrg_test_contaminate_text returned %d for %s\n",
		       ret, contaminate_sym_name);
		return -EFAULT;
	}
	return 0;
}

/* This is a harmless MSR bit flip
 * The X86_EFLAGS_FIXED bit is supposed to be always 1
 * but surprisingly nothing happens if it's set to 0
 * NOTE: you need to enable MSR validation in lkrg
 */
static int lkrg_test_flip_register(void)
{
	u64 ctrl, tmp;
	pr_info("lkrg_test: flipping MSR register " REGNAME "\n");
	rdmsrl(MSR, ctrl);
	pr_debug(REGNAME " before: %llx \n", ctrl);
	ctrl ^= FLIP;
	wrmsrl(MSR, ctrl);
	rdmsrl(MSR, tmp);
	pr_debug(REGNAME " after: %llx \n", tmp);
	if (ctrl != tmp) {
		pr_err("Failed to flip " REGNAME " bits\n");
		return -EFAULT;
	} else {
		pr_info("lkrg_test: flipped MSR register " REGNAME " on CPU %d\n", smp_processor_id());
	}

	return 0;
}

static ssize_t lkrg_test_proc_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	char buf[LKRG_TEST_MAX_CMD];
	char *cmd;
	size_t n;
	int ret = 0;

	if (count == 0)
		return 0;

	n = min_t(size_t, count, sizeof(buf) - 1);
	if (copy_from_user(buf, ubuf, n))
		return -EFAULT;
	buf[n] = '\0';

	/* strip trailing and leading whitespace */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
			 buf[n - 1] == '\t' || buf[n - 1] == ' '))
		buf[--n] = '\0';

	cmd = buf;
	while (*cmd == '\n' || *cmd == '\r' || *cmd == '\t' || *cmd == ' ')
		cmd++;

	if (*cmd == '\0') {
		*ppos += count;
		return count;
	}

	pr_debug("lkrg_test: command '%s'\n", cmd);
	if (!strcmp(cmd, "contaminate_core")) {
		ret = lkrg_test_contaminate_kernel_core();
		if (ret)
			return ret;
	} else if (!strcmp(cmd, "flip_msr")) {
		ret = lkrg_test_flip_register();
		if (ret)
			return ret;
	} else {
		pr_info("lkrg_test: unknown command '%s'\n", cmd);
		return -EINVAL;
	}

	*ppos += (loff_t) count;
	return (ssize_t) count;
}

static const struct proc_ops lkrg_test_proc_ops = {
	.proc_write = lkrg_test_proc_write,
	.proc_lseek = noop_llseek,
};

static int __init lkrg_test_init(void)
{
	int ret = lkrg_test_contaminate_init();
	if (ret)
		return ret;
	lkrg_test_proc = proc_create(LKRG_TEST_PROCFS_PATH, 0222, NULL,
				     &lkrg_test_proc_ops);
	if (!lkrg_test_proc) {
		pr_err("lkrg_test: proc_create failed\n");
		return -ENOMEM;
	}
	pr_info("lkrg_test: loaded, write to /proc/%s\n",
		LKRG_TEST_PROCFS_PATH);
	return 0;
}

static void __exit lkrg_test_exit(void)
{
	if (lkrg_test_proc)
		proc_remove(lkrg_test_proc);
	pr_info("lkrg_test: unloaded\n");
}

module_init(lkrg_test_init);
module_exit(lkrg_test_exit);

MODULE_AUTHOR("Greg Sokol");
MODULE_DESCRIPTION("LKRG test - see LKRG in action at its best");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
