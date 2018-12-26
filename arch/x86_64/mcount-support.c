#include <assert.h>
#include <string.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/internal.h"
#include "utils/filter.h"
#include "utils/arch.h"

int mcount_get_register_arg(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx;

	switch (spec->type) {
	case ARG_TYPE_REG:
		reg_idx = spec->reg_idx;
		break;
	case ARG_TYPE_INDEX:
		reg_idx = spec->idx; /* for integer arguments */
		break;
	case ARG_TYPE_FLOAT:
		reg_idx = spec->idx + UFT_X86_64_REG_FLOAT_BASE;
		break;
	case ARG_TYPE_STACK:
	default:
		return -1;
	}

	switch (reg_idx) {
	case UFT_X86_64_REG_RDI:
		ctx->val.i = ARG1(regs);
		break;
	case UFT_X86_64_REG_RSI:
		ctx->val.i = ARG2(regs);
		break;
	case UFT_X86_64_REG_RDX:
		ctx->val.i = ARG3(regs);
		break;
	case UFT_X86_64_REG_RCX:
		ctx->val.i = ARG4(regs);
		break;
	case UFT_X86_64_REG_R8:
		ctx->val.i = ARG5(regs);
		break;
	case UFT_X86_64_REG_R9:
		ctx->val.i = ARG6(regs);
		break;
	case UFT_X86_64_REG_XMM0:
		asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_X86_64_REG_XMM1:
		asm volatile ("movsd %%xmm1, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_X86_64_REG_XMM2:
		asm volatile ("movsd %%xmm2, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_X86_64_REG_XMM3:
		asm volatile ("movsd %%xmm3, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_X86_64_REG_XMM4:
		asm volatile ("movsd %%xmm4, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_X86_64_REG_XMM5:
		asm volatile ("movsd %%xmm5, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_X86_64_REG_XMM6:
		asm volatile ("movsd %%xmm6, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_X86_64_REG_XMM7:
		asm volatile ("movsd %%xmm7, %0\n" : "=m" (ctx->val.v));
		break;
	default:
		return -1;
	}

	return 0;
}

void mcount_get_stack_arg(struct mcount_arg_context *ctx,
			  struct uftrace_arg_spec *spec)
{
	int offset;

	switch (spec->type) {
	case ARG_TYPE_STACK:
		offset = spec->stack_ofs;
		break;
	case ARG_TYPE_INDEX:
		offset = spec->idx - ARCH_MAX_REG_ARGS;
		break;
	case ARG_TYPE_FLOAT:
		offset = (spec->idx - ARCH_MAX_FLOAT_REGS) * 2 - 1;
		break;
	case ARG_TYPE_REG:
	default:
		/* should not reach here */
		pr_err_ns("invalid stack access for arguments\n");
		break;
	}

	if (offset < 1 || offset > 100)
		pr_dbg("invalid stack offset: %d\n", offset);

	memcpy(ctx->val.v, ctx->stack_base + offset, spec->size);
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct uftrace_arg_spec *spec)
{
	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	/* type of return value cannot be FLOAT, so check format instead */
	if (spec->fmt != ARG_FMT_FLOAT)
		memcpy(ctx->val.v, ctx->retval, spec->size);
	else if (spec->size == 10) /* for long double type */
		asm volatile ("fstpt %0\n\tfldt %0" : "=m" (ctx->val.v));
	else
		asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->val.v));
}

void mcount_save_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->xmm[0]));
	asm volatile ("movsd %%xmm1, %0\n" : "=m" (ctx->xmm[1]));
	asm volatile ("movsd %%xmm2, %0\n" : "=m" (ctx->xmm[2]));
	asm volatile ("movsd %%xmm3, %0\n" : "=m" (ctx->xmm[3]));
	asm volatile ("movsd %%xmm4, %0\n" : "=m" (ctx->xmm[4]));
	asm volatile ("movsd %%xmm5, %0\n" : "=m" (ctx->xmm[5]));
	asm volatile ("movsd %%xmm6, %0\n" : "=m" (ctx->xmm[6]));
	asm volatile ("movsd %%xmm7, %0\n" : "=m" (ctx->xmm[7]));
}

void mcount_restore_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile ("movsd %0, %%xmm0\n" :: "m" (ctx->xmm[0]));
	asm volatile ("movsd %0, %%xmm1\n" :: "m" (ctx->xmm[1]));
	asm volatile ("movsd %0, %%xmm2\n" :: "m" (ctx->xmm[2]));
	asm volatile ("movsd %0, %%xmm3\n" :: "m" (ctx->xmm[3]));
	asm volatile ("movsd %0, %%xmm4\n" :: "m" (ctx->xmm[4]));
	asm volatile ("movsd %0, %%xmm5\n" :: "m" (ctx->xmm[5]));
	asm volatile ("movsd %0, %%xmm6\n" :: "m" (ctx->xmm[6]));
	asm volatile ("movsd %0, %%xmm7\n" :: "m" (ctx->xmm[7]));
}
