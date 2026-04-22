# lkrg_test
Linux kernel module that illustrates how LKRG runtime protection works.

## LKRG
Linux Kernel Runtime Guard is a runtime exploit scanner which scans for typical artifacts following a successfully utilised exploit.

Please visit the module's official website https://lkrg.org/ for more details on the project.

There's a conference video featuring its author - Adam Pi3 - who explains how the module works. Presentation slides can also be found there.

## The mechanisms
LKRG implements a variety of integrity tests, such as:

- Kernel code integrity
- CPU state integrity
- Process credentials integrity
- Process namespace bindings

## The test

Currently this test simulates the following integrity violations:

- Kernel code contamination
- CPU register updates

### Building

`make -C <path_to_kernel_source_tree_or_headers> M=<path_to_module_source> modules`

`make -C <path_to_kernel_source_tree_or_headers> M=<path_to_module_source> modules_install`

### Running

#### Start LKRG

CPU state violation relies on flipping a rather harmless bit in `MSR_SYSCALL_MASK` MSR. In order to enable MSR checks in LKRG the module needs to be loaded with `msr_validate=1` argument.
By default LKRG will panic the kernel whenever it detects kernel integrity violation. It can be loaded with `kint_enforce=1` to make it issue a warning without panicking.
Setting a higher log level via `log_level=4` might also be a good idea.

`modprobe lkrg kint_enforce=1 msr_validate=1 log_level=4`

#### Load lkrg_test

Modprobe first, no arguments required

`modprobe lkrg_test`

A `procfs` node should appear under `/proc/lkrg_test`

- Writing `contaminate_core` to the procfs node will overwrite 4 bytes at the address of `kgdb_arch_init`. Unless you need to debug the kernel using kgdb this should be a harmless operation.
- Writing `flip_msr` will flip `X86_EFLAGS_FIXED` bit in `MSR_SYSCALL_MASK`. The bit should be set to 1 but resetting it turns out to be harmless.

**Example**

`echo contaminate_core > /proc/lkrg_test`
