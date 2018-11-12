#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "uftrace.h"
#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define TRAMP_ENT_SIZE    24  /* size of trampoilne for each entry */
#define TRAMP_ADR_SIZE    16  /* module id + addres of plthook_addr() */
#define TRAMP_PCREL_PUSH  11  /* PC-relative offset for PUSH (module_id) */
#define TRAMP_PCREL_JMP   17  /* PC_relative offset for JMP */
#define TRAMP_IDX_OFFSET  1
#define TRAMP_MOD_OFFSET  7
#define TRAMP_JMP_OFFSET  13

extern void __weak plt_hooker(void);
struct plthook_data * mcount_arch_hook_no_plt(struct uftrace_elf_data *elf,
					      const char *modname,
					      unsigned long offset)
{
	struct plthook_data *pd;
	void *trampoline;
	size_t tramp_len;
	uint32_t i;
	const uint8_t tramp_insns[] = {  /* make stack what plt_hooker expect */
		/* PUSH child_idx */
		0x68, 0, 0, 0, 0,
		/* PUSH module_id */
		0xff, 0x35, 0, 0, 0, 0,
		/* JMP plthook_addr */
		0xff, 0x25, 0, 0, 0, 0,
		/* should never reach here */
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	};
	void *plthook_addr = plt_hooker;
	void *tramp;

	pd = xzalloc(sizeof(*pd));
	pd->module_id = (unsigned long)pd;
	pd->base_addr = offset;

	if (load_elf_dynsymtab(&pd->dsymtab, elf, offset, 0) < 0) {
		free(pd);
		return NULL;
	}

	tramp_len = pd->dsymtab.nr_sym * TRAMP_ENT_SIZE + TRAMP_ADR_SIZE;
	trampoline = mmap(NULL, tramp_len, PROT_READ|PROT_WRITE,
			  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (trampoline == MAP_FAILED) {
		pr_dbg("mmap failed: %m: ignore libcall hooking\n");
		free(pd);
		return NULL;
	}

	pd->resolved_addr = xcalloc(pd->dsymtab.nr_sym, sizeof(long));

	/* add trampoline - save orig addr and replace GOT */
	pr_dbg2("module: %s (id: %lx), addr = %lx, PLTGOT = %p\n",
		pd->mod_name, pd->module_id, pd->base_addr, pd->pltgot_ptr);

	for (i = 0; i < pd->dsymtab.nr_sym; i++) {
		uint32_t pcrel;

		tramp = trampoline + i * TRAMP_ENT_SIZE;

		/* copy trampoline instructions */
		memcpy(tramp, tramp_insns, TRAMP_ENT_SIZE);

		/* update offset (child id) */
		memcpy(tramp + TRAMP_IDX_OFFSET, &i, sizeof(i));

		/* update module id */
		pcrel = trampoline + tramp_len - TRAMP_ADR_SIZE
			- (tramp + TRAMP_PCREL_PUSH);
		memcpy(tramp + TRAMP_MOD_OFFSET, &pcrel, sizeof(pcrel));

		/* update jump offset */
		pcrel = trampoline + tramp_len - TRAMP_ADR_SIZE + sizeof(long)
			- (tramp + TRAMP_PCREL_JMP);
		memcpy(tramp + TRAMP_JMP_OFFSET, &pcrel, sizeof(pcrel));

		pd->resolved_addr[i] = *(unsigned long *)pd->dsymtab.sym[i].addr;
		*(unsigned long *)pd->dsymtab.sym[i].addr = (unsigned long)tramp;
	}

	tramp = trampoline + i * TRAMP_ENT_SIZE;
	memcpy(tramp, &pd->module_id, sizeof(pd->module_id));

	tramp += sizeof(long);
	memcpy(tramp, &plthook_addr, sizeof(plthook_addr));

	mprotect(trampoline, tramp_len, PROT_READ|PROT_EXEC);

	pd->mod_name = xstrdup(modname);
	return pd;
}
