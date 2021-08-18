/*
 * Copyright 2019-2021, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "llvm_jit.h"

#include "llvm_jit_bootstrap.h"

#include "mem.h"
#include "sqlInt.h"
#include "vdbeInt.h"
#include "whereInt.h"
#include "vdbe.h"

#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/LLJIT.h"
#include "llvm-c/OrcEE.h"
#include "llvm-c/Target.h"

/**
 * This part of the build context remains persistent for the whole construction
 * process.
 */
static const size_t llvm_build_ctx_init_sz =
	offsetof(struct llvm_build_ctx, fn_id);

/** Used for callback function name generation. */
static const char *const fn_name_prefix = "expr_";

/** Types referenced during construction of LLVM IR. */
static LLVMTypeRef llvm_vdbe_type;
static LLVMTypeRef llvm_vdbe_ptr_type;
static LLVMTypeRef llvm_mem_type;
static LLVMTypeRef llvm_mem_ptr_type;
static LLVMTypeRef llvm_func_type;
static LLVMTypeRef llvm_func_ptr_type;

/** Auxiliary functions referenced during construction of LLVM IR. */
static LLVMValueRef llvm_mem_copy;
static LLVMValueRef llvm_mem_set_null;
static LLVMValueRef llvm_mem_set_int;
static LLVMValueRef llvm_mem_set_bool;
static LLVMValueRef llvm_mem_set_double;
static LLVMValueRef llvm_mem_set_str0_static;
static LLVMValueRef llvm_vdbe_op_next;
static LLVMValueRef llvm_vdbe_op_realify;
static LLVMValueRef llvm_vdbe_op_column;
static LLVMValueRef llvm_vdbe_op_fetch;
static LLVMValueRef llvm_vdbe_op_aggstep0;
static LLVMValueRef llvm_vdbe_op_aggstep;
static LLVMValueRef llvm_vdbe_op_aggfinal;

/** LLVM Orc LLJIT instance. */
static LLVMOrcLLJITRef llvm_lljit;
/* FIXME: should be disposed sometime? */

/**
 * Module containing type definitions and referenced auxiliary function
 * prototypes. Other modules are cloned from it.
 */
static LLVMModuleRef llvm_bootstrap_module;

/**
 * Create the base module from an embedded LLVM bitcode string, populate the
 * base types.
 */
static bool
llvm_load_bootstrap_module(void);

/** Diagnostic handler for internal LLVM errors. */
static
void llvm_diag_handler(LLVMDiagnosticInfoRef di, void *unused);

/**
 * Callback function passed to LLVMOrcLLJITBuilderSetObjectLinkingLayerCreator:
 * creates a default object linking layer.
 */
static LLVMOrcObjectLayerRef
llvm_obj_linking_layer_create(void *unused1, LLVMOrcExecutionSessionRef es,
			      const char *unused2);

/** Create an LLVM Orc LLJIT instance. */
static bool
llvm_lljit_inst_create(LLVMTargetMachineRef tm);

/**
 * Retrieve the error message string from LLVMErrorRef and disposes it,
 * preliminarily saving the error message to the static buffer.
 */
static const char *
llvm_get_err_msg(LLVMErrorRef err);

static LLVMValueRef
llvm_get_fn(LLVMModuleRef m, LLVMValueRef extern_fn);

/** Callback function passed to LLVMOrcExecutionSessionSetErrorReporter. */
static void
llvm_log_jit_error(void *unused, LLVMErrorRef err);

/** Add the current module to LLJIT. */
static bool
llvm_lljit_add_module(struct llvm_jit_ctx *jit_ctx);

static void
llvm_build_cb_ini(struct llvm_jit_ctx *jit_ctx);

static bool
llvm_build_agg_loop_ini(struct llvm_jit_ctx *jit_ctx, AggInfo *agg_info);

static bool
llvm_build_agg_loop_body(struct llvm_jit_ctx *jit_ctx, AggInfo *agg_info);

static void
llvm_build_agg_loop_fin(struct llvm_build_ctx *build_ctx, WhereLevel *where_lvl,
			AggInfo *agg_info);

/** Build the current expression. */
static bool
llvm_build_expr(struct llvm_build_ctx *ctx);

static bool
llvm_build_agg_column(struct llvm_build_ctx *ctx);

/** Build a column reference value. */
static bool
llvm_build_col_ref(struct llvm_build_ctx *build_ctx);

/** Build an integer value. */
static bool
llvm_build_int(struct llvm_build_ctx *ctx, bool is_neg);

/** Build a boolean value. */
static void
llvm_build_bool(struct llvm_build_ctx *ctx);

/** Build a double precision floating point value. */
static bool
llvm_build_double(struct llvm_build_ctx *ctx, const char *z, bool is_neg);

/** Build null-terminated string value. */
static bool
llvm_build_str(struct llvm_build_ctx *build_ctx, const char *z);

/** Build a null value. */
static void
llvm_build_null(struct llvm_build_ctx *ctx);

/** Build a call to vdbe_op_column and check its return code. */
static bool
llvm_build_vdbe_op_column(struct llvm_build_ctx *ctx, int tab, int col);

/** Build a call to mem_copy and check its return code. */
static void
llvm_build_mem_copy(struct llvm_build_ctx *ctx, int src_reg_idx,
		    int tgt_reg_idx);

/** Build a return code check. */
static void
llvm_build_rc_check(struct llvm_build_ctx *ctx, LLVMValueRef llvm_rc);

bool
llvm_session_init(void)
{
	sql *sql;
	LLVMPassRegistryRef llvm_gl_pass_reg;
	LLVMContextRef llvm_gl_ctx;
	const char *llvm_triple;
	LLVMTargetRef llvm_t;
	LLVMTargetMachineRef default_tm;
	char *err_msg;
	char *cpu_name;
	char *cpu_feats;

	sql = sql_get();
	assert(sql);
	assert(!sql->llvm_session_init);
	llvm_gl_pass_reg = LLVMGetGlobalPassRegistry();
	assert(llvm_gl_pass_reg);
	LLVMInitializeCore(llvm_gl_pass_reg);
	llvm_gl_ctx = LLVMGetGlobalContext();
	assert(llvm_gl_ctx);
	LLVMContextSetDiagnosticHandler(llvm_gl_ctx, llvm_diag_handler, NULL);
	if (LLVMInitializeNativeTarget() != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to initialize native target");
		return false;
	}
	if (LLVMInitializeNativeAsmParser() != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to initialize native asm parser");
		return false;
	}
	if (LLVMInitializeNativeAsmPrinter() != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to initialize native asm printer");
		return false;
	}
	if (!llvm_load_bootstrap_module())
		return false;
	llvm_triple = LLVMGetTarget(llvm_bootstrap_module);
	assert(llvm_triple);
	if (LLVMGetTargetFromTriple(llvm_triple, &llvm_t, &err_msg) != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to get target from triple: %s", err_msg);
		LLVMDisposeErrorMessage(err_msg);
		err_msg = NULL;
		return false;
	}
	if (!LLVMTargetHasJIT(llvm_t)) {
		/* FIXME: move to diag_set */
		say_error("target machine does not support JIT: please, "
			  "turn JIT option off");
		return true;
	}
	cpu_name = LLVMGetHostCPUName();
	assert(cpu_name);
	cpu_feats = LLVMGetHostCPUFeatures();
	assert(cpu_feats);
	say_info("LLVMJIT detected CPU '%s', with features '%s'",
		 cpu_name, cpu_feats);
	default_tm = LLVMCreateTargetMachine(llvm_t, llvm_triple,
					     cpu_name, cpu_feats,
					     LLVMCodeGenLevelDefault,
					     LLVMRelocDefault,
					     LLVMCodeModelJITDefault);
	assert(default_tm);
	LLVMDisposeMessage(cpu_name);
	cpu_name = NULL;
	LLVMDisposeMessage(cpu_feats);
	cpu_feats = NULL;
	if (!llvm_lljit_inst_create(default_tm))
		return false;
	sql->llvm_session_init = true;
	return true;
}

struct llvm_jit_ctx *
llvm_jit_ctx_new(Parse *parse_ctx)
{
	assert(parse_ctx);

	size_t jit_ctx_sz;
	struct llvm_jit_ctx *jit_ctx;
	LLVMContextRef llvm_m_ctx;
	LLVMModuleRef m;
	size_t build_ctx_sz;
	struct llvm_build_ctx *build_ctx;

	jit_ctx_sz = sizeof(struct llvm_jit_ctx);
	jit_ctx = sqlMalloc(jit_ctx_sz);
	if (!jit_ctx) {
		diag_set(OutOfMemory, jit_ctx_sz, "sqlMalloc",
			 "struct llvm_jit_ctx");
		return NULL;
	}
	/* FIXME: should use a thread-safe context instead of a global one? */
	m = jit_ctx->module = LLVMModuleCreateWithName("tnt_sql");
	assert(m);
	llvm_m_ctx = LLVMGetModuleContext(m);
	assert(llvm_m_ctx);
	LLVMContextSetDiagnosticHandler(llvm_m_ctx, llvm_diag_handler, NULL);
	jit_ctx->rt = NULL;
	jit_ctx->compiled = false;
	build_ctx_sz = sizeof(struct llvm_build_ctx);
	build_ctx = jit_ctx->build_ctx =
	region_alloc(&parse_ctx->region, build_ctx_sz);
	if (!build_ctx) {
		diag_set(OutOfMemory, build_ctx_sz, "region_alloc",
			 "struct llvm_build_ctx");
		return NULL;
	}
	build_ctx->module = m;
	build_ctx->builder = LLVMCreateBuilder();
	build_ctx->parse_ctx = parse_ctx;
	/* FIXME: is this safe to do? */
	memset((char *)build_ctx + llvm_build_ctx_init_sz, 0,
	       build_ctx_sz - llvm_build_ctx_init_sz);
	jit_ctx->cnt = 0;
	return jit_ctx;
}

void
llvm_jit_ctx_delete(struct llvm_jit_ctx *ctx)
{
	LLVMOrcResourceTrackerRef rt;
	LLVMOrcExecutionSessionRef es;
	LLVMOrcSymbolStringPoolRef ssp;
	LLVMErrorRef err;

	if (!ctx)
		return;
	if (!ctx->compiled) {
		assert(ctx->module);
		LLVMDisposeModule(ctx->module);
		ctx->module = NULL;
	}
	rt = ctx->rt;
	if (rt) {
		err = LLVMOrcResourceTrackerRemove(rt);
		if (err) {
			const char *err_msg;

			err_msg = llvm_get_err_msg(err);
			assert(err_msg);
			/* FIXME: move to diag_set */
			say_error("failed to remove resource tracker: %s",
				  err_msg);
			/* FIXME: should return status? */
			return;
		}
		LLVMOrcReleaseResourceTracker(rt);
	}
	es = LLVMOrcLLJITGetExecutionSession(llvm_lljit);
	assert(es);
	ssp = LLVMOrcExecutionSessionGetSymbolStringPool(es);
	assert(ssp);
	LLVMOrcSymbolStringPoolClearDeadEntries(ssp);
	sql_free(ctx);
}

void
llvm_build_expr_list_ini(struct llvm_jit_ctx *jit_ctx, int src_regs_idx,
			 int tgt_regs_idx)
{
	assert(jit_ctx);
	assert(src_regs_idx >= 0);
	assert(tgt_regs_idx > 0);

	struct llvm_build_ctx *build_ctx;

	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	llvm_build_cb_ini(jit_ctx);
	build_ctx->src_regs_idx = src_regs_idx;
	build_ctx->tgt_regs_idx = tgt_regs_idx;
}

bool
llvm_build_expr_list_item(struct llvm_jit_ctx *jit_ctx,
			  struct ExprList_item *item, int expr_idx, int flags)
{
	assert(jit_ctx);
	assert(item);
	assert(expr_idx >= 0);

	struct llvm_build_ctx *build_ctx;
	LLVMBuilderRef b;
	Expr *expr;
	int tgt_regs_idx;
	int tgt_reg_idx;
	LLVMValueRef llvm_tgt_reg_idx;
	const char *name;
	LLVMValueRef llvm_tgt_reg;
	int j;

	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	b = build_ctx->builder;
	assert(b);
	expr = build_ctx->expr = item->pExpr;
	assert(expr);
	tgt_regs_idx = build_ctx->tgt_regs_idx;
	assert(tgt_regs_idx > 0);
	tgt_reg_idx = build_ctx->tgt_reg_idx = tgt_regs_idx + expr_idx;
	if ((flags & SQL_ECEL_REF) != 0
	    && (j = item->u.x.iOrderByCol) > 0) {
		assert((flags & SQL_ECEL_OMITREF) == 0);

		int src_regs_idx;
		int src_reg_idx;

		src_regs_idx = build_ctx->src_regs_idx;
		assert(src_regs_idx >= 0);
		src_reg_idx = src_regs_idx + j - 1;
		llvm_build_mem_copy(build_ctx, src_reg_idx, tgt_reg_idx);
		return true;
	}
	llvm_tgt_reg_idx = build_ctx->llvm_tgt_reg_idx =
		LLVMConstInt(LLVMInt32Type(), tgt_reg_idx , false);
	assert(llvm_tgt_reg_idx);
	name = tt_sprintf("tgt_reg_%d", expr_idx);
	assert(name);
	llvm_tgt_reg = build_ctx->llvm_tgt_reg =
		LLVMBuildInBoundsGEP2(b, llvm_mem_type, build_ctx->llvm_regs,
				      &llvm_tgt_reg_idx, 1, name);
	assert(llvm_tgt_reg);
	return llvm_build_expr(build_ctx);
}

bool
llvm_build_expr_list_fin(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx);

	LLVMModuleRef m;
	struct llvm_build_ctx *build_ctx;
	LLVMBuilderRef b;
	LLVMValueRef llvm_fn;
	size_t build_ctx_sz;
	LLVMValueRef llvm_ok;
	char *err_msg;

	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	b = build_ctx->builder;
	assert(b);
	m = jit_ctx->module;
	assert(m);
	llvm_fn = build_ctx->llvm_fn;
	assert(llvm_fn);
	build_ctx_sz = sizeof(struct llvm_build_ctx);
	memset((char *)build_ctx + llvm_build_ctx_init_sz, 0,
	       build_ctx_sz - llvm_build_ctx_init_sz);
	llvm_ok = LLVMConstInt(LLVMInt1Type(), true, false);
	assert(llvm_ok);
	ALWAYS(LLVMBuildRet(b, llvm_ok));
	if (LLVMPrintModuleToFile(m, "tnt_sql.ll", &err_msg) != 0) {
		/* FIXME: move to diag_set */
		say_error("printing module to file failed: %s", err_msg);
		LLVMDisposeMessage(err_msg);
		err_msg = NULL;
		return false;
	}
	if (LLVMVerifyFunction(llvm_fn, LLVMPrintMessageAction) != 0) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "function IR verification failed");
		return false;
	}
	return true;
}

bool
llvm_build_agg_loop(struct llvm_jit_ctx *jit_ctx, WhereInfo *where_info,
		    AggInfo *agg_info)
{
	assert(jit_ctx != NULL);
	assert(where_info != NULL);
	assert(agg_info != NULL);

	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);
	WhereLevel *where_lvl = &where_info->a[0];
	assert(where_lvl != NULL);
	Parse *parse_ctx = build_ctx->parse_ctx;
	assert(parse_ctx != NULL);
	Vdbe *vdbe = parse_ctx->pVdbe;
	assert(vdbe != NULL);
	int fn_id;
	int col_ref_meta_cnt;
	struct llvm_col_ref_meta *col_ref_meta;

	if (!llvm_build_agg_loop_ini(jit_ctx, agg_info))
		return false;
	if (!llvm_build_agg_loop_body(jit_ctx, agg_info))
		return false;
	llvm_build_agg_loop_fin(build_ctx, where_lvl, agg_info);
	fn_id = build_ctx->fn_id;
	assert(fn_id >= 0);
	col_ref_meta_cnt = build_ctx->col_ref_meta_cnt;
	assert(col_ref_meta_cnt >= 0);
	col_ref_meta = build_ctx->col_ref_meta;
	assert(col_ref_meta == 0 || col_ref_meta != 0);
	sqlVdbeAddOp4(vdbe, OP_ExecJITCallback, fn_id, col_ref_meta_cnt, 0,
		      (const char *)col_ref_meta, P4_PTR);
	VdbeComment((vdbe, "Callback for evaluating aggregate query"));
	vdbe->llvm_jit_enabled = true;
	sqlVdbeResolveLabel(vdbe, where_lvl->addrBrk);
	sqlVdbeResolveLabel(vdbe, where_info->iBreak);
	sqlWherePostEnd(where_info);
	return true;
}

bool
llvm_exec_compiled_expr_list(struct llvm_jit_ctx *ctx, int fn_id, Vdbe *vdbe)
{
	assert(ctx);
	assert(fn_id >= 0);
	assert(vdbe);

	const char *fn_name;
	LLVMOrcJITTargetAddress fn_addr;
	LLVMErrorRef err;
	const char *err_msg;

	if (!ctx->compiled && !llvm_lljit_add_module(ctx))
		return -1;
	fn_name = tt_sprintf("%s%d", fn_name_prefix, fn_id);
	assert(fn_name);
	assert(llvm_lljit);
	err = LLVMOrcLLJITLookup(llvm_lljit, &fn_addr, fn_name);
	if (err) {
		err_msg = llvm_get_err_msg(err);
		assert(err_msg);
		diag_set(ClientError, ER_LLVM_IR_COMPILATION, err_msg);
		return false;
	}
	if (!fn_addr) {
		err_msg = llvm_get_err_msg(err);
		assert(err_msg);
		diag_set(ClientError, ER_LLVM_IR_COMPILATION, err_msg);
		return false;
	}
	return ((bool (*) (Vdbe *))fn_addr)(vdbe);
}

bool
llvm_jit_fin(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx);

	LLVMModuleRef m;
	struct llvm_build_ctx *build_ctx;
	LLVMBuilderRef b;
	char *err_msg;

	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	b = build_ctx->builder;
	assert(b);
	LLVMDisposeBuilder(b);
	m = jit_ctx->module;
	if (LLVMPrintModuleToFile(m, "tnt_sql.ll", &err_msg) != 0) {
		/* FIXME: move to diag_set */
		say_error("printing module to file failed: %s", err_msg);
		LLVMDisposeMessage(err_msg);
		err_msg = NULL;
		return false;
	}
	if (LLVMVerifyModule(m, LLVMReturnStatusAction, &err_msg) != 0) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION, err_msg);
		LLVMDisposeMessage(err_msg);
		err_msg = NULL;
		return false;
	}
	return true;
}

void
llvm_jit_change_col_refs_to_reg_copies(struct llvm_jit_ctx *jit_ctx,
				       struct llvm_col_ref_meta *col_ref_meta,
				       int col_ref_meta_cnt, int tab,
				       int coro_src_regs_idx)
{
	assert(jit_ctx);
	assert(col_ref_meta_cnt >= 0);
	assert(tab >= 0);
	assert(coro_src_regs_idx >= 0);

	int i;
	struct llvm_col_ref_meta *p;
	for (i = 0, p = col_ref_meta; i < col_ref_meta_cnt; ++i, ++p) {
		assert(p);

		LLVMBasicBlockRef op_col_begin_bb;
		LLVMBasicBlockRef op_col_end_bb;
		LLVMValueRef op_col_end_val;
		LLVMBasicBlockRef pred_bb;
		LLVMBasicBlockRef bb;
		LLVMValueRef br_instr;
		int col;
		int coro_src_reg_idx;
		int tgt_reg_idx;
		struct llvm_build_ctx *build_ctx;
		LLVMBuilderRef b;
		LLVMValueRef llvm_fn;
		LLVMValueRef llvm_regs;

		if (p->tab != tab)
			continue;
		op_col_begin_bb = p->bb_begin;
		assert(op_col_begin_bb);
		pred_bb = LLVMGetPreviousBasicBlock(op_col_begin_bb);
		assert(pred_bb);
		br_instr = LLVMGetLastInstruction(pred_bb);
		assert(br_instr);
		ALWAYS(LLVMIsABranchInst(br_instr));
		LLVMInstructionEraseFromParent(br_instr);
		br_instr = NULL;
		build_ctx = jit_ctx->build_ctx;
		assert(build_ctx);
		llvm_fn = build_ctx->llvm_fn = p->llvm_fn;
		assert(llvm_fn);
		b = build_ctx->builder;
		assert(b);
		LLVMPositionBuilderAtEnd(b, pred_bb);
		op_col_end_bb = p->bb_end;
		assert(op_col_end_bb);
		assert(op_col_begin_bb != op_col_end_bb);
		bb = LLVMGetPreviousBasicBlock(op_col_begin_bb);
		assert(bb);
		pred_bb = NULL;
		do {
			bb = LLVMGetNextBasicBlock(bb);
			assert(bb);
			if (pred_bb)
				LLVMDeleteBasicBlock(pred_bb);
			pred_bb = bb;
		} while (bb != op_col_end_bb);
		p->bb_begin = NULL;
		op_col_end_val = LLVMBasicBlockAsValue(op_col_end_bb);
		assert(op_col_end_val);
		LLVMSetValueName2(op_col_end_val, "aux", strlen("aux"));
		col = p->col;
		assert(col >= 0);
		coro_src_reg_idx = coro_src_regs_idx + col;
		tgt_reg_idx = p->tgt_reg_idx;
		assert(tgt_reg_idx > 0);
		llvm_regs = build_ctx->llvm_regs = p->llvm_regs;
		assert(llvm_regs);
		llvm_build_mem_copy(build_ctx, coro_src_reg_idx, tgt_reg_idx);
		ALWAYS(LLVMBuildBr(b, op_col_end_bb));
	}
}

void
llvm_jit_patch_idx_col_refs(struct llvm_jit_ctx *jit_ctx, WhereLevel *where_lvl,
			    struct llvm_col_ref_meta *col_ref_meta,
			    int col_ref_meta_cnt)
{
	assert(jit_ctx);
	assert(where_lvl);

	struct llvm_build_ctx *build_ctx;
	LLVMBuilderRef b;
	WhereLoop *where_loop;
	int curr_tab;
	int idx;
	int i;
	struct llvm_col_ref_meta *p;

	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	b = build_ctx->builder;
	assert(b);
	where_loop = where_lvl->pWLoop;
	assert(where_loop);
	curr_tab = where_lvl->iTabCur;
	assert(curr_tab >= 0);
	idx = where_lvl->iIdxCur;
	assert(idx >= 0);
	i = 0;
	p = col_ref_meta;
	for (; i < col_ref_meta_cnt; ++i, ++p) {
		assert(p);

		int tab;
		LLVMValueRef llvm_idx;
		LLVMValueRef llvm_tab;
		LLVMValueRef llvm_tab_store;
		LLVMBasicBlockRef bb;
		struct index_def *idx_def;
		uint32_t j;
		struct key_part *key_part;

		tab = p->tab;
		assert(tab >= 0);
		if (tab != curr_tab)
			continue;
		p->tab = idx;
		llvm_idx = LLVMConstInt(LLVMInt32Type(), idx, false);
		assert(llvm_idx);
		llvm_tab = p->llvm_tab_var;
		assert(llvm_tab);
		llvm_tab_store = p->llvm_tab_store;
		assert(llvm_tab_store);
		bb = p->bb_begin;
		assert(bb);
		LLVMPositionBuilder(b, bb, llvm_tab_store);
		p->llvm_tab_store = LLVMBuildStore(b, llvm_idx, llvm_tab);
		assert(p->llvm_tab_store);
		LLVMInstructionEraseFromParent(llvm_tab_store);
		llvm_tab_store = NULL;
		if (!(where_loop->wsFlags & WHERE_AUTO_INDEX))
			continue;
		idx_def = where_loop->index_def;
		assert(idx_def);
		struct key_def *key_def = idx_def->key_def;
		assert(key_def);
		uint32_t part_cnt = key_def->part_count;
		for (j = 0, key_part = key_def->parts; j < part_cnt; ++j, ++key_part) {
			assert(key_part);

			int col;

			col = p->col;
			assert(col >= 0);
			if (key_part->fieldno == (uint32_t)col) {
				LLVMValueRef llvm_eph_idx_col;
				LLVMValueRef llvm_col;
				LLVMValueRef llvm_col_store;

				p->col = (int)j;
				llvm_eph_idx_col =
					LLVMConstInt(LLVMInt32Type(), j, false);
				llvm_col = p->llvm_col_var;
				assert(llvm_col);
				llvm_col_store = p->llvm_col_store;
				assert(llvm_col_store);
				LLVMPositionBuilder(b, bb, llvm_col_store);
				p->llvm_col_store =
					LLVMBuildStore(b, llvm_eph_idx_col, llvm_col);
				assert(p->llvm_col_store);
				LLVMInstructionEraseFromParent(llvm_col_store);
				llvm_col_store = NULL;
				break;
			}
		}
	}
}

static bool
llvm_load_bootstrap_module(void)
{
	LLVMMemoryBufferRef buf;
	size_t len;
	LLVMModuleRef m;
	LLVMContextRef m_ctx;
	struct load_type {
		const char *name;
		LLVMTypeRef *type;
		bool is_ptr;
	} const load_types[] = {
	{ "struct.Vdbe", &llvm_vdbe_type, false },
	{ "struct.Vdbe", &llvm_vdbe_ptr_type, true },
	{ "struct.Mem", &llvm_mem_type, false },
	{ "struct.Mem", &llvm_mem_ptr_type, true },
	{ "struct.func", &llvm_func_type, false },
	{ "struct.func", &llvm_func_ptr_type, true },
	};
	struct load_fn {
		const char *name;
		LLVMValueRef *llvm_fn;
	} const load_fns[] = {
	{ "mem_copy", &llvm_mem_copy },
	{ "mem_set_null", &llvm_mem_set_null },
	{ "mem_set_int", &llvm_mem_set_int },
	{ "mem_set_bool", &llvm_mem_set_bool },
	{ "mem_set_double", &llvm_mem_set_double },
	{ "mem_set_str0_static", &llvm_mem_set_str0_static },
	{ "vdbe_op_next", &llvm_vdbe_op_next },
	{ "vdbe_op_realify", &llvm_vdbe_op_realify },
	{ "vdbe_op_column", &llvm_vdbe_op_column },
	{ "vdbe_op_fetch", &llvm_vdbe_op_fetch },
	{ "vdbe_op_aggstep0", &llvm_vdbe_op_aggstep0 },
	{ "vdbe_op_aggstep", &llvm_vdbe_op_aggstep },
	{ "vdbe_op_aggfinal", &llvm_vdbe_op_aggfinal },
	};

	len = lengthof(llvm_jit_bootstrap_bin);
	buf = LLVMCreateMemoryBufferWithMemoryRange((const char *)llvm_jit_bootstrap_bin,
						    len, NULL, false);
	assert(buf);
	if (LLVMParseBitcode2(buf, &llvm_bootstrap_module) != 0) {
		/* FIXME: move to diag_set */
		say_error("parsing of LLVM bitcode failed");
		return false;
	}
	LLVMDisposeMemoryBuffer(buf);
	buf = NULL;
	m = llvm_bootstrap_module;
	assert(m);
	m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx);
	LLVMContextSetDiagnosticHandler(m_ctx, llvm_diag_handler, NULL);
	for (size_t i = 0; i < lengthof(load_types); ++i) {
		struct load_type load_type;
		LLVMTypeRef type;

		load_type = load_types[i];
		type = LLVMGetTypeByName(m, load_type.name);
		if (type == NULL) {
			/* FIXME: move to diag_set */
			say_error("failed to find type: %s", load_type.name);
			return false;
		}
		*load_type.type =
			load_type.is_ptr ? LLVMPointerType(type, 0) : type;
	}
	for (size_t i = 0; i < lengthof(load_fns); ++i) {
		struct load_fn load_fn;
		LLVMValueRef llvm_fn;

		load_fn = load_fns[i];
		llvm_fn = *load_fn.llvm_fn =
			LLVMGetNamedFunction(m, load_fn.name);
		if (llvm_fn == NULL) {
			/* FIXME: move to diag_set */
			say_error("failed to load function '%s'", load_fn.name);
			return false;
		}
	}
	return true;
}

static
void llvm_diag_handler(LLVMDiagnosticInfoRef di, void *unused) {
	assert(di);
	(void)unused;

	const char *diag_info_descr;

	diag_info_descr = LLVMGetDiagInfoDescription(di);
	assert(diag_info_descr);
	/* FIXME: move to diag_set */
	say_error("error occurred during JIT'ing: %s", diag_info_descr);
}

static LLVMOrcObjectLayerRef
llvm_obj_linking_layer_create(void *unused1, LLVMOrcExecutionSessionRef es,
			      const char *unused2)
{
	(void)unused1;
	(void)unused2;

	LLVMOrcObjectLayerRef ol;

	ol = LLVMOrcCreateRTDyldObjectLinkingLayerWithSectionMemoryManager(es);
	return ol;
}

static LLVMValueRef
llvm_get_fn(LLVMModuleRef m, LLVMValueRef extern_fn)
{
	assert(m);
	assert(extern_fn);

	LLVMValueRef internal_fn;
	LLVMTypeRef fn_type;
	const char *fn_name;
	size_t unused;

	fn_name = LLVMGetValueName2(extern_fn, &unused);
	assert(fn_name);
	internal_fn = LLVMGetNamedFunction(m, fn_name);
	if (internal_fn)
		return internal_fn;
	fn_type = LLVMGetElementType(LLVMTypeOf(extern_fn));
	assert(fn_type);
	internal_fn = LLVMAddFunction(m, fn_name, fn_type);
	assert(internal_fn);
	return internal_fn;
}

static void
llvm_log_jit_error(void *unused, LLVMErrorRef err)
{
	(void)unused;
	assert(err);

	const char *err_msg;

	err_msg = llvm_get_err_msg(err);
	assert(err_msg);
	/* FIXME: move to diag_set */
	say_error("error occurred during JIT'ing: %s", err_msg);
}

static const char *
llvm_get_err_msg(LLVMErrorRef err)
{
	assert(err);

	char *orig;
	const char *cp;

	orig = LLVMGetErrorMessage(err);
	assert(orig);
	cp = tt_cstr(orig, strlen(orig));
	assert(cp);
	LLVMDisposeErrorMessage(orig);
	orig = NULL;
	return cp;
}

static bool
llvm_lljit_inst_create(LLVMTargetMachineRef tm)
{
	assert(tm);

	LLVMOrcJITTargetMachineBuilderRef jtmb;
	LLVMOrcLLJITBuilderRef lljit_builder;
	LLVMOrcExecutionSessionRef es;
	char lljit_gl_prefix;
	LLVMOrcDefinitionGeneratorRef dg;
	LLVMOrcJITDylibRef jd;
	LLVMErrorRef err;

	lljit_builder = LLVMOrcCreateLLJITBuilder();
	assert(lljit_builder);
	jtmb = LLVMOrcJITTargetMachineBuilderCreateFromTargetMachine(tm);
	assert(jtmb);
	LLVMOrcLLJITBuilderSetJITTargetMachineBuilder(lljit_builder, jtmb);
	LLVMOrcLLJITBuilderSetObjectLinkingLayerCreator(lljit_builder,
							llvm_obj_linking_layer_create,
							NULL);
	err = LLVMOrcCreateLLJIT(&llvm_lljit, lljit_builder);
	if (err) {
		const char *err_msg;

		err_msg = llvm_get_err_msg(err);
		assert(err_msg);
		/* FIXME: move to diag_set */
		say_error("failed to create LLJIT instance: %s", err_msg);
		return false;
	}
	assert(llvm_lljit);
	es = LLVMOrcLLJITGetExecutionSession(llvm_lljit);
	assert(es);
	LLVMOrcExecutionSessionSetErrorReporter(es, llvm_log_jit_error, NULL);
	/*
	 * Symbol resolution support for symbols in the tarantool binary.
	 */
	lljit_gl_prefix = LLVMOrcLLJITGetGlobalPrefix(llvm_lljit);
	err = LLVMOrcCreateDynamicLibrarySearchGeneratorForProcess(&dg,
								   lljit_gl_prefix,
								   NULL, NULL);
	if (err) {
		const char *err_msg;

		err_msg = llvm_get_err_msg(err);
		assert(err_msg);
		/* FIXME: move to diag_set */
		say_error("failed to create generator: %s", err_msg);
		return false;
	}
	jd = LLVMOrcLLJITGetMainJITDylib(llvm_lljit);
	assert(jd);
	LLVMOrcJITDylibAddGenerator(jd, dg);
	return true;
}

static bool
llvm_lljit_add_module(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx);

	LLVMModuleRef m;
	LLVMOrcThreadSafeContextRef llvm_ts_ctx;
	LLVMOrcThreadSafeModuleRef tsm;
	LLVMOrcJITDylibRef jd;
	LLVMOrcResourceTrackerRef rt;
	LLVMErrorRef err;

	m = jit_ctx->module;
	assert(m);
	llvm_ts_ctx = LLVMOrcCreateNewThreadSafeContext();
	assert(llvm_ts_ctx);
	tsm = LLVMOrcCreateNewThreadSafeModule(m, llvm_ts_ctx);
	assert(tsm);
	LLVMOrcDisposeThreadSafeContext(llvm_ts_ctx);
	jit_ctx->module = NULL; /* Ownership transferred to thread-safe module. */
	assert(llvm_lljit);
	jd = LLVMOrcLLJITGetMainJITDylib(llvm_lljit);
	rt = jit_ctx->rt = LLVMOrcJITDylibCreateResourceTracker(jd);
	assert(rt);
	/*
	 * NB: This does not actually compile code. That happens lazily the first
	 * time a symbol defined in the module is requested.
	 */
	err = LLVMOrcLLJITAddLLVMIRModuleWithRT(llvm_lljit, rt, tsm);
	if (err) {
		const char *err_msg;

		err_msg = llvm_get_err_msg(err);
		assert(err_msg);
		diag_set(ClientError, ER_LLVM_IR_COMPILATION, err_msg);
		return false;
	}
	jit_ctx->compiled = true;
	return true;
}

static void
llvm_build_cb_ini(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx);

	LLVMModuleRef m;
	LLVMTargetDataRef td;
	LLVMBuilderRef b;
	struct llvm_build_ctx *build_ctx;
	int fn_id;
	LLVMValueRef llvm_fn;
	const char *fn_name;
	LLVMTypeRef llvm_fn_type;
	LLVMTypeRef fn_param_types[1];
	LLVMBasicBlockRef entry_bb;
	LLVMValueRef llvm_vdbe;
	u32 vdbe_aMem_idx;
	LLVMValueRef llvm_regs_ptr;
	LLVMValueRef llvm_regs;

	m = jit_ctx->module;
	assert(m);
	td = LLVMGetModuleDataLayout(m);
	assert(td);
	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	fn_id = build_ctx->fn_id = jit_ctx->cnt++;
	assert(fn_id >= 0);
	b = build_ctx->builder;
	assert(b);
	assert(fn_id >= 0);
	assert(llvm_vdbe_ptr_type);
	fn_param_types[0] = llvm_vdbe_ptr_type;
	llvm_fn_type = LLVMFunctionType(LLVMInt1Type(), fn_param_types,
					lengthof(fn_param_types), false);
	fn_name = tt_sprintf("%s%d", fn_name_prefix, build_ctx->fn_id);
	assert(fn_name);
	llvm_fn = build_ctx->llvm_fn = LLVMAddFunction(m, fn_name, llvm_fn_type);
	assert(llvm_fn);
	LLVMSetLinkage(llvm_fn, LLVMExternalLinkage);
	LLVMSetVisibility(llvm_fn, LLVMDefaultVisibility);
	entry_bb = LLVMAppendBasicBlock(llvm_fn, "entry");
	assert(entry_bb);
	LLVMPositionBuilderAtEnd(b, entry_bb);
	llvm_vdbe = build_ctx->llvm_vdbe = LLVMGetParam(llvm_fn, 0);
	assert(llvm_vdbe);
	vdbe_aMem_idx = LLVMElementAtOffset(td, llvm_vdbe_type,
					    offsetof(Vdbe, aMem));
	llvm_regs_ptr = LLVMBuildStructGEP2(b, llvm_vdbe_type, llvm_vdbe,
					    vdbe_aMem_idx, "regs_ptr");
	assert(llvm_regs_ptr);
	llvm_regs = build_ctx->llvm_regs =
		LLVMBuildLoad2(b, llvm_mem_ptr_type, llvm_regs_ptr, "regs");
	assert(llvm_regs);
}

static bool
llvm_build_agg_loop_ini(struct llvm_jit_ctx *jit_ctx, AggInfo *agg_info)
{
	assert(jit_ctx != NULL);
	assert(agg_info != NULL);

	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);
	LLVMModuleRef m = build_ctx->module;
	assert(m != NULL);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b);
	LLVMValueRef llvm_vdbe;
	Parse *parse_ctx = build_ctx->parse_ctx;
	assert(parse_ctx != NULL);
	struct region region = parse_ctx->region;;
	LLVMValueRef *llvm_sql_ctx;
	size_t agg_meta_sz;
	int i;
	struct AggInfo_func *func;

	llvm_sql_ctx = region_alloc_array(&region, typeof(LLVMValueRef),
					  agg_info->nFunc, &agg_meta_sz);
	if (llvm_sql_ctx == NULL) {
		diag_set(OutOfMemory, agg_meta_sz, "region_alloc_array",
			 "struct llvm_agg_meta");
		parse_ctx->is_aborted = true;
		return false;
	}
	llvm_build_cb_ini(jit_ctx);
	llvm_vdbe = build_ctx->llvm_vdbe;
	assert(llvm_vdbe != NULL);
	assert(agg_info->aFunc != NULL);
	assert(agg_info->nFunc > 0);
	for (i = 0, func = agg_info->aFunc; i < agg_info->nFunc; ++i, ++func) {
		unsigned long long int func_addr =
			(unsigned long long int)func->func;
		LLVMValueRef llvm_func_addr =
			LLVMConstInt(LLVMInt64Type(), func_addr, false);
		assert(llvm_func_addr != NULL);
		LLVMValueRef llvm_func =
			LLVMConstIntToPtr(llvm_func_addr, llvm_func_ptr_type);
		assert(llvm_func != NULL);
		Expr *expr = func->pExpr;
		assert(expr != NULL);
		ExprList *expr_list = expr->x.pList;
		assert(!ExprHasProperty(expr, EP_xIsSelect));
		int argc = expr_list != NULL ? expr_list->nExpr : 0;
		assert(argc >= 0);
		LLVMValueRef llvm_argc =
			LLVMConstInt(LLVMInt32Type(), argc, false);
		assert(llvm_argc != NULL);
		LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_vdbe_op_aggstep0);
		assert(llvm_fn != NULL);
		LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
		assert(llvm_fn_type != NULL);
		LLVMValueRef llvm_fn_args[] = {llvm_vdbe, llvm_func, llvm_argc};
		unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
		const char *name = tt_sprintf("sql_context_%d", i);
		assert(name != NULL);

		llvm_sql_ctx[i] =
			LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				       llvm_fn_args_cnt, name);
	}
	build_ctx->llvm_agg_sql_ctx = llvm_sql_ctx;
	return true;
}

static bool
llvm_build_agg_loop_body(struct llvm_jit_ctx *jit_ctx, AggInfo *agg_info)
{
	assert(jit_ctx != NULL);
	assert(agg_info != NULL);

	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);
	LLVMModuleRef m = build_ctx->module;
	assert(m != NULL);
	LLVMContextRef m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx != NULL);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
	Parse *parse_ctx = build_ctx->parse_ctx;
	assert(parse_ctx != NULL);
	LLVMValueRef llvm_vdbe = build_ctx->llvm_vdbe;
	assert(llvm_vdbe != NULL);
	LLVMValueRef *llvm_sql_ctx = build_ctx->llvm_agg_sql_ctx;
	assert(llvm_sql_ctx != NULL);
	LLVMBasicBlockRef loop_bb;
	int i;
	struct AggInfo_func *func;
	struct AggInfo_col *col;

	loop_bb = build_ctx->agg_loop_bb =
		LLVMCreateBasicBlockInContext(m_ctx, "agg_loop");
	assert(loop_bb != NULL);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, loop_bb);
	LLVMBuildBr(b, loop_bb);
	LLVMPositionBuilderAtEnd(b, loop_bb);
	assert(agg_info->aFunc != NULL);
	assert(agg_info->nFunc >= 0);
	agg_info->directMode = 1;
	for (i = 0, func = agg_info->aFunc; i < agg_info->nFunc; ++i, ++func) {
		Expr *expr = func->pExpr;
		assert(expr != NULL);
		ExprList *arg_list = expr->x.pList;
		assert(!ExprHasProperty(expr, EP_xIsSelect));
		int argc = 0;
		int arg_regs_idx = 0;
		assert(func->iMem >= 0);
		LLVMValueRef llvm_acc_reg_idx =
			LLVMConstInt(LLVMInt32Type(), func->iMem, false);
		LLVMValueRef llvm_argc;
		LLVMValueRef llvm_arg_regs_idx;
		LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_vdbe_op_aggstep);
		assert(llvm_fn != NULL);
		LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
		assert(llvm_fn_type != NULL);
		LLVMValueRef llvm_fn_args[4];
		unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
		LLVMValueRef llvm_rc;

		if (arg_list != NULL) {
			int j;
			struct ExprList_item *item;

			argc = arg_list->nExpr;
			arg_regs_idx = sqlGetTempRange(parse_ctx, argc);
			assert(arg_regs_idx > 0 && arg_regs_idx <= parse_ctx->nMem);
			build_ctx->tgt_regs_idx = arg_regs_idx;
			assert(arg_list->a != NULL);
			for (j = 0, item = arg_list->a; j < argc; ++j, ++item) {
				Expr *arg = item->pExpr;
				assert(arg != NULL);

				if (!llvm_build_expr_list_item(jit_ctx, item, j, 0))
					return false;
			}
		}
		assert(func->iDistinct < 0);
		assert(!sql_func_flag_is_set(func->func, SQL_FUNC_NEEDCOLL));
		llvm_argc = LLVMConstInt(LLVMInt32Type(), argc, false);
		assert(llvm_argc != NULL);
		llvm_arg_regs_idx = LLVMConstInt(LLVMInt32Type(), arg_regs_idx, false);
		assert(llvm_arg_regs_idx != NULL);
		llvm_fn_args[0] = llvm_vdbe;
		llvm_fn_args[1] = llvm_sql_ctx[i];
		llvm_fn_args[2] = llvm_acc_reg_idx;
		llvm_fn_args[3] = llvm_arg_regs_idx;
		llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				    llvm_fn_args_cnt, "rc");
		llvm_build_rc_check(build_ctx, llvm_rc);
		sql_expr_type_cache_change(parse_ctx, arg_regs_idx, argc);
		sqlReleaseTempRange(parse_ctx, arg_regs_idx, argc);
	}
	sqlExprCacheClear(parse_ctx);
	for (i = 0, col = agg_info->aCol; i < agg_info->nAccumulator; ++i, ++col) {
		Expr *expr = col->pExpr;
		assert(expr != NULL);
		int tgt_reg_idx = col->iMem;
		assert(tgt_reg_idx > 0);
		LLVMValueRef llvm_tgt_reg_idx = build_ctx->llvm_tgt_reg_idx =
			LLVMConstInt(LLVMInt32Type(), tgt_reg_idx , false);
		assert(llvm_tgt_reg_idx != NULL);
		LLVMValueRef llvm_tgt_reg = build_ctx->llvm_tgt_reg =
			LLVMBuildInBoundsGEP2(b, llvm_mem_type, build_ctx->llvm_regs,
					      &llvm_tgt_reg_idx, 1, "acc_reg");
		assert(llvm_tgt_reg != NULL);

		build_ctx->expr = expr;
		build_ctx->tgt_reg_idx = tgt_reg_idx;
		if (!llvm_build_expr(build_ctx))
			return false;
	}
	agg_info->directMode = 0;
	sqlExprCacheClear(parse_ctx);
	return true;
}

static void
llvm_build_agg_loop_fin(struct llvm_build_ctx *build_ctx, WhereLevel *where_lvl,
			AggInfo *agg_info)
{
	assert(build_ctx != NULL);
	assert(where_lvl != NULL);
	assert(agg_info != NULL);

	LLVMModuleRef m = build_ctx->module;
	assert(m != NULL);
	LLVMContextRef m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx != NULL);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
	LLVMValueRef llvm_vdbe = build_ctx->llvm_vdbe;
	assert(llvm_vdbe != NULL);
	int csr = where_lvl->p1;
	assert(csr > 0);
	LLVMValueRef llvm_csr = LLVMConstInt(LLVMInt32Type(), csr, false);
	assert(llvm_csr != NULL);
	int res = where_lvl->p3;
	LLVMValueRef llvm_res = LLVMConstInt(LLVMInt32Type(), res, false);
	assert(llvm_res != NULL);
	assert(res == 0 || res == 1);
	int event_cntr = where_lvl->p5;
	LLVMValueRef llvm_event_cntr =
		LLVMConstInt(LLVMInt32Type(), event_cntr, false);
	assert(llvm_event_cntr != NULL);
	LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_vdbe_op_next);
	assert(llvm_fn != NULL);
	LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type != NULL);
	LLVMValueRef llvm_fn_args[] =
		{ llvm_vdbe, llvm_csr, llvm_res, llvm_event_cntr };
	unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
	LLVMValueRef llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
					 llvm_fn_args_cnt, "rc");
	LLVMBasicBlockRef loop_exit_bb =
		LLVMCreateBasicBlockInContext(m_ctx, "agg_loop_exit");
	assert(loop_exit_bb != NULL);
	LLVMBasicBlockRef continue_bb =
		LLVMCreateBasicBlockInContext(m_ctx, "continue");
	assert(continue_bb != NULL);
	LLVMBasicBlockRef abort_bb =
		LLVMCreateBasicBlockInContext(m_ctx, "abort");
	assert(abort_bb != NULL);
	LLVMValueRef switch_instr =
		LLVMBuildSwitch(b, llvm_rc, loop_exit_bb, 2);
	assert(switch_instr != NULL);
	LLVMValueRef llvm_continue = LLVMConstInt(LLVMInt32Type(), 1, false);
	assert(llvm_continue != NULL);
	LLVMValueRef llvm_abort = LLVMConstInt(LLVMInt32Type(), -1, false);
	assert(llvm_abort != NULL);
	LLVMBasicBlockRef loop_bb = build_ctx->agg_loop_bb;
	assert(loop_bb != NULL);
	LLVMValueRef llvm_err = LLVMConstInt(LLVMInt1Type(), false, false);
	WhereLoop *where_loop = where_lvl->pWLoop;
	assert(where_loop != NULL);
	int i;
	struct AggInfo_func *func;
	LLVMValueRef *llvm_sql_ctx = build_ctx->llvm_agg_sql_ctx;
	assert(llvm_sql_ctx != NULL);
	LLVMValueRef llvm_ok = LLVMConstInt(LLVMInt1Type(), true, false);

	LLVMAddCase(switch_instr, llvm_continue, continue_bb);
	LLVMAddCase(switch_instr, llvm_abort, abort_bb);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, continue_bb);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, abort_bb);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, loop_exit_bb);
	LLVMPositionBuilderAtEnd(b, continue_bb);
	ALWAYS(LLVMBuildBr(b, loop_bb) != NULL);
	LLVMPositionBuilderAtEnd(b, abort_bb);
	ALWAYS(LLVMBuildRet(b, llvm_err) != NULL);
	LLVMPositionBuilderAtEnd(b, loop_exit_bb);
	assert((where_loop->wsFlags && WHERE_IN_ABLE == 0) ||
	       where_lvl->u.in.nIn <= 0);
	assert(where_lvl->addrSkip == 0);
	assert(where_lvl->iLeftJoin == 0);
	assert(agg_info->aFunc != NULL);
	assert(agg_info->nFunc > 0);
	for (i = 0, func = agg_info->aFunc; i < agg_info->nFunc; ++i, ++func) {
		LLVMValueRef llvm_fn_args[] = { llvm_vdbe, llvm_sql_ctx[i] };

		llvm_fn = llvm_get_fn(m, llvm_vdbe_op_aggfinal);
		assert(llvm_fn != NULL);
		llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
		assert(llvm_fn_type != NULL);
		llvm_fn_args_cnt = lengthof(llvm_fn_args);
		ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				      llvm_fn_args_cnt, "") != NULL);
	}
	ALWAYS(LLVMBuildRet(b, llvm_ok) != NULL);
}

static bool
llvm_build_expr(struct llvm_build_ctx *ctx)
{
	assert(ctx);

	Expr *expr;
	int op;

	expr = ctx->expr;
	assert(expr);
	op = !expr ? TK_NULL : expr->op;
	switch (op) {
	case TK_AGG_COLUMN:
		return llvm_build_agg_column(ctx);
	case TK_COLUMN_REF:
		return llvm_build_col_ref(ctx);
	case TK_INTEGER:
		return llvm_build_int(ctx, false);
	case TK_TRUE:
	case TK_FALSE:
		llvm_build_bool(ctx);
		return true;
	case TK_FLOAT:
		assert(!ExprHasProperty(expr, EP_IntValue));
		return llvm_build_double(ctx, expr->u.zToken, false);
	case TK_STRING:
		assert(!ExprHasProperty(expr, EP_IntValue));
		return llvm_build_str(ctx, expr->u.zToken);
	case TK_NULL:
		llvm_build_null(ctx);
		return true;
	case TK_UPLUS:
		ctx->expr = expr->pLeft;
		assert(ctx->expr != NULL);
		return llvm_build_expr(ctx);
	default:
		unreachable();
	}
}

static bool
llvm_build_agg_column(struct llvm_build_ctx *ctx)
{
	assert(ctx);

	Expr *expr;
	AggInfo *agg_info;
	struct AggInfo_col *agg_info_col;

	expr = ctx->expr;
	assert(expr);
	agg_info = expr->pAggInfo;
	assert(agg_info);
	assert(expr->iAgg >= 0);
	agg_info_col = &agg_info->aCol[expr->iAgg];
	if (!agg_info->directMode) {
		assert(agg_info_col->iMem > 0);

		int tgt_reg_idx;

		tgt_reg_idx = ctx->tgt_reg_idx;
		assert(tgt_reg_idx > 0);
		if (agg_info_col->iMem == tgt_reg_idx)
			return true;
		llvm_build_mem_copy(ctx, agg_info_col->iMem, tgt_reg_idx);
		return true;
	} else if (agg_info->useSortingIdx) {
		struct space_def *space_def;

		space_def = agg_info_col->space_def;
		assert(space_def);
		assert(agg_info->sortingIdxPTab >= 0);
		assert(agg_info_col->iSorterColumn >= 0);

		if (!llvm_build_vdbe_op_column(ctx, agg_info->sortingIdxPTab,
					       agg_info_col->iSorterColumn))
			return false;
		if (space_def->fields[expr->iAgg].type == FIELD_TYPE_NUMBER) {
			LLVMModuleRef m;
			LLVMBuilderRef b;
			LLVMValueRef llvm_vdbe;
			LLVMValueRef llvm_tgt_reg_idx;
			LLVMValueRef llvm_fn;
			LLVMTypeRef llvm_fn_type;
			LLVMValueRef llvm_fn_args[2];
			unsigned int llvm_fn_args_cnt;

			m = ctx->module;
			assert(m);
			b = ctx->builder;
			assert(b);
			llvm_vdbe = ctx->llvm_vdbe;
			assert(llvm_vdbe);
			llvm_tgt_reg_idx = ctx->llvm_tgt_reg_idx;
			assert(llvm_tgt_reg_idx);
			llvm_fn = llvm_get_fn(m, llvm_vdbe_op_realify);
			assert(llvm_fn);
			llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
			assert(llvm_fn_type);
			llvm_fn_args[0] = llvm_vdbe;
			llvm_fn_args[1] = llvm_tgt_reg_idx;
			llvm_fn_args_cnt = lengthof(llvm_fn_args);
			ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn,
					      llvm_fn_args, llvm_fn_args_cnt, ""));
			return true;
		}
		return true;
	}
	return llvm_build_col_ref(ctx);
}

static bool
llvm_build_col_ref(struct llvm_build_ctx *build_ctx)
{
	assert(build_ctx);

	LLVMModuleRef m;
	LLVMContextRef m_ctx;
	LLVMBuilderRef b;
	Expr *expr;
	int tab;
	int col;
	Parse *parse_ctx;
	LLVMValueRef llvm_regs;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_tgt_reg_idx;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	unsigned int llvm_fn_args_cnt;
	LLVMValueRef llvm_vdbe;
	LLVMValueRef llvm_rc;
	int i;
	struct yColCache *p;

	m = build_ctx->module;
	assert(m);
	m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx);
	b = build_ctx->builder;
	assert(b);
	expr = build_ctx->expr;
	assert(expr);
	tab = expr->iTable;
	col = expr->iColumn;
	assert(col >= 0);
	parse_ctx = build_ctx->parse_ctx;
	assert(parse_ctx);
	llvm_vdbe = build_ctx->llvm_vdbe;
	assert(llvm_vdbe);
	llvm_tgt_reg = build_ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	llvm_tgt_reg_idx = build_ctx->llvm_tgt_reg_idx;
	assert(llvm_tgt_reg_idx);
	if (tab < 0) {
		if (parse_ctx->vdbe_field_ref_reg > 0) {
			LLVMTargetDataRef td;
			int vdbe_field_ref_reg_idx;
			LLVMValueRef llvm_vdbe_field_ref_reg_idx;
			LLVMValueRef llvm_field_idx;
			LLVMValueRef llvm_fn_args[4];

			td = LLVMGetModuleDataLayout(m);
			assert(td);
			vdbe_field_ref_reg_idx = parse_ctx->vdbe_field_ref_reg;
			assert(vdbe_field_ref_reg_idx >= 0);
			llvm_vdbe_field_ref_reg_idx =
				LLVMConstInt(LLVMInt32Type(),
					     vdbe_field_ref_reg_idx, false);
			assert(llvm_vdbe_field_ref_reg_idx);
			llvm_fn = llvm_get_fn(m, llvm_vdbe_op_fetch);
			assert(llvm_fn);
			llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
			assert(llvm_fn_type);
			llvm_field_idx = LLVMConstInt(LLVMInt32Type(), col, false);
			assert(llvm_field_idx);
			llvm_fn_args[0] = llvm_vdbe;
			llvm_fn_args[1] = llvm_vdbe_field_ref_reg_idx;
			llvm_fn_args[2] = llvm_field_idx;
			llvm_fn_args[3] = llvm_tgt_reg_idx;
			llvm_fn_args_cnt = lengthof(llvm_fn_args);
			llvm_rc =
				LLVMBuildCall2(b, llvm_fn_type, llvm_fn,
					       llvm_fn_args, llvm_fn_args_cnt, "rc");
			assert(llvm_rc);
			llvm_build_rc_check(build_ctx, llvm_rc);
			return true;
		} else {
			/*
			 * Coding an expression that is part of an index where
			 * column names in the index refer to the table to which
			 * the index belongs.
			 */
			tab = parse_ctx->iSelfTab;
		}
	}
	llvm_regs = build_ctx->llvm_regs;
	assert(llvm_regs);
	for (i = 0, p = parse_ctx->aColCache; i < parse_ctx->nColCache; ++i, ++p) {
		assert(p->iTable >= 0);
		assert(p->iColumn >= 0);
		if (p->iTable == tab && p->iColumn == col) {
			p->lru = parse_ctx->iCacheCnt++;
			assert(p->lru >= 0);
			assert(p->iReg > 0);

			LLVMValueRef llvm_idx;
			const char *name;
			LLVMValueRef llvm_cached_column_reg;
			LLVMValueRef llvm_fn_args[2];

			sqlExprCachePinRegister(parse_ctx, p->iReg);
			llvm_idx = LLVMConstInt(LLVMInt64Type(), p->iReg, false);
			assert(llvm_idx);
			name = "cached_col_reg";
			llvm_cached_column_reg =
				LLVMBuildInBoundsGEP2(b, llvm_mem_type,
						      llvm_regs, &llvm_idx, 1,
						      name);
			assert(llvm_cached_column_reg);
			/* FIXME: copy operation depending on SQL_ECEL_DUP */
			llvm_fn = llvm_get_fn(m, llvm_mem_copy);
			assert(llvm_fn);
			llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
			assert(llvm_fn_type);
			llvm_fn_args[0] = llvm_tgt_reg;
			llvm_fn_args[1] =llvm_cached_column_reg;
			llvm_fn_args_cnt = lengthof(llvm_fn_args);
			llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn,
						 llvm_fn_args, llvm_fn_args_cnt, "");
			llvm_build_rc_check(build_ctx, llvm_rc);
			return true;
		}
	}
	return llvm_build_vdbe_op_column(build_ctx, tab, col);
}

static bool
llvm_build_int(struct llvm_build_ctx *ctx, bool is_neg)
{
	assert(ctx);

	LLVMModuleRef m;
	LLVMBuilderRef b;
	const char *z;
	const char *sign;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_val;
	LLVMValueRef llvm_is_neg;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	Expr *expr;
	LLVMValueRef llvm_fn_args[3];
	unsigned int llvm_fn_args_cnt;

	m = ctx->module;
	assert(m);
	b = ctx->builder;
	assert(b);
	llvm_fn = llvm_get_fn(m, llvm_mem_set_int);
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	expr = ctx->expr;
	assert(expr);
	llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	if (expr->flags & EP_IntValue) {
		int val;

		val = expr->u.iValue;
		assert(val >= 0);
		if (is_neg)
			val = -val;
		llvm_val = LLVMConstInt(LLVMInt64Type(), val, is_neg);
		assert(llvm_val);
		llvm_is_neg = LLVMConstInt(LLVMInt1Type(), is_neg, false);
		assert(llvm_is_neg);
		llvm_fn_args[0] = llvm_tgt_reg;
		llvm_fn_args[1] = llvm_val;
		llvm_fn_args[2] = llvm_is_neg;
		ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				      lengthof(llvm_fn_args), ""));
		return true;
	}

	int64_t val;

	z = expr->u.zToken;
	assert(z);
	sign = is_neg ? "-" : "";
	if (z[0] == '0' && (z[1] == 'x' || z[1] == 'X')) {
		errno = 0;
		if (is_neg) {
			val = strtoll(z, NULL, 16);
		} else {
			/* FIXME: use unsigned integer instead of signed */
			val = strtoull(z, NULL, 16);
			/*
			 * FIXME: why is this comparison correct? I would
			 * expect it to be (uint64_t)val > INT64_MAX.
			 */
			if (val > INT64_MAX)
				goto int_overflow;
		}
		if (errno != 0) {
			diag_set(ClientError, ER_HEX_LITERAL_MAX, sign, z,
				 strlen(z) - 2, 16);
			return false;
		}
	} else {
		size_t len;
		bool unused;

		len = strlen(z);
		if (sql_atoi64(z, &val, &unused, len) != 0 ||
		    (!is_neg && (uint64_t) val > INT64_MAX)) {
int_overflow:
			diag_set(ClientError, ER_INT_LITERAL_MAX, sign, z);
			return false;
		}
	}
	if (is_neg)
		val = -val;
	llvm_val = LLVMConstInt(LLVMInt64Type(), val, is_neg);
	assert(llvm_val);
	llvm_is_neg = LLVMConstInt(LLVMInt1Type(), is_neg, false);
	assert(llvm_is_neg);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args[1] = llvm_val;
	llvm_fn_args[2] = llvm_is_neg;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args, llvm_fn_args_cnt, ""));
	return true;
}

static void
llvm_build_bool(struct llvm_build_ctx *ctx)
{
	assert(ctx);

	LLVMModuleRef m;
	LLVMBuilderRef b;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_val;
	Expr *expr;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[2];
	unsigned int llvm_fn_args_cnt;

	m = ctx->module;
	assert(m);
	b = ctx->builder;
	assert(b);
	expr = ctx->expr;
	assert(expr);
	llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	llvm_val = LLVMConstInt(LLVMInt1Type(), expr->op == TK_TRUE, false);
	assert(llvm_val);
	llvm_fn = llvm_get_fn(m, llvm_mem_set_bool);
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args[1] = llvm_val;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args, llvm_fn_args_cnt, ""));
}

static bool
llvm_build_double(struct llvm_build_ctx *ctx, const char *z, bool is_neg)
{
	assert(ctx);
	assert(z);

	LLVMModuleRef m;
	LLVMBuilderRef b;
	int len;
	double val;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_val;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[2];
	unsigned int llvm_fn_args_cnt;

	m = ctx->module;
	assert(m);
	b = ctx->builder;
	assert(b);
	/* FIXME: is this conversion legit? */
	len = sqlStrlen30(z);
	assert(len > 0);
	if (sqlAtoF(z, &val, len) == 0) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "failed to convert string to double");
		return false;
	}
	assert(!sqlIsNaN(val));
	if (is_neg)
		val = -val;
	llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	llvm_val = LLVMConstReal(LLVMDoubleType(), val);
	assert(llvm_val);
	llvm_fn = llvm_get_fn(m, llvm_mem_set_double);
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args[1] = llvm_val ;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
			      llvm_fn_args_cnt, ""));
	return true;
}

static bool
llvm_build_str(struct llvm_build_ctx *build_ctx, const char *z)
{
	assert(build_ctx);
	assert(z);

	LLVMModuleRef m;
	LLVMBuilderRef b;
	int len;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_z;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[2];
	unsigned int llvm_fn_args_cnt;

	m = build_ctx->module;
	assert(m);
	b = build_ctx->builder;
	assert(b);
	/* FIXME: is this conversion legit? */
	len = sqlStrlen30(z);
	/* FIXME: what is the best way to handle this? */
	if (len > build_ctx->parse_ctx->db->aLimit[SQL_LIMIT_LENGTH]) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "string or blob too big");
		return false;
	}
	llvm_tgt_reg = build_ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	llvm_z = LLVMBuildGlobalStringPtr(b, z, "");
	assert(llvm_z);
	llvm_fn = llvm_get_fn(m, llvm_mem_set_str0_static);
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args[1] = llvm_z;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args, llvm_fn_args_cnt, ""));
	return true;
}

static void
llvm_build_null(struct llvm_build_ctx *ctx)
{
	assert(ctx != NULL);

	LLVMModuleRef m;
	LLVMBuilderRef b;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[1];
	unsigned int llvm_fn_args_cnt;

	m = ctx->module;
	assert(m);
	b = ctx->builder;
	assert(b);
	llvm_fn = llvm_get_fn(m, llvm_mem_set_null);
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args, llvm_fn_args_cnt, ""));
}

static bool
llvm_build_vdbe_op_column(struct llvm_build_ctx *ctx, int tab, int col)
{
	assert(ctx);
	assert(tab >= 0);
	assert(col >= 0);

	LLVMModuleRef m;
	LLVMContextRef m_ctx;
	LLVMBuilderRef b;
	Expr *expr;
	Parse *parse_ctx;
	LLVMValueRef llvm_regs;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_tgt_reg_idx;
	int tgt_reg_idx;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[4];
	unsigned int llvm_fn_args_cnt;
	LLVMValueRef llvm_curr_fn;
	LLVMBasicBlockRef curr_bb;
	LLVMBasicBlockRef op_col_begin_bb;
	LLVMBasicBlockRef op_col_end_bb;
	LLVMValueRef llvm_vdbe;
	LLVMValueRef llvm_tab_var;
	LLVMValueRef llvm_tab_imm;
	LLVMValueRef llvm_tab_store;
	LLVMValueRef llvm_col_var;
	LLVMValueRef llvm_col_imm;
	LLVMValueRef llvm_col_store;
	LLVMValueRef llvm_rc;
	struct region *region;
	int col_ref_meta_cnt;
	struct llvm_col_ref_meta curr_col_ref_meta;
	struct llvm_col_ref_meta *col_ref_meta;
	size_t col_ref_meta_sz;

	m = ctx->module;
	assert(m);
	m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx);
	b = ctx->builder;
	assert(b);
	expr = ctx->expr;
	assert(expr);
	parse_ctx = ctx->parse_ctx;
	assert(parse_ctx);
	llvm_vdbe = ctx->llvm_vdbe;
	assert(llvm_vdbe);
	llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	llvm_tgt_reg_idx = ctx->llvm_tgt_reg_idx;
	assert(llvm_tgt_reg_idx);
	llvm_regs = curr_col_ref_meta.llvm_regs = ctx->llvm_regs;
	assert(llvm_regs);
	tgt_reg_idx = ctx->tgt_reg_idx;
	assert(tgt_reg_idx > 0);
	llvm_curr_fn = curr_col_ref_meta.llvm_fn = ctx->llvm_fn;
	assert(llvm_curr_fn);
	curr_bb =  LLVMGetInsertBlock(b);
	assert(curr_bb);
	op_col_begin_bb = curr_col_ref_meta.bb_begin =
	LLVMCreateBasicBlockInContext(m_ctx, "OP_Column_begin");
	assert(op_col_begin_bb);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, op_col_begin_bb);
	LLVMBuildBr(b, op_col_begin_bb);
	LLVMPositionBuilderAtEnd(b, op_col_begin_bb);
	curr_col_ref_meta.tab = tab;
	curr_col_ref_meta.col = col;
	llvm_tab_var = curr_col_ref_meta.llvm_tab_var =
		LLVMBuildAlloca(b, LLVMInt32Type(), "tab");
	assert(llvm_tab_var);
	llvm_tab_imm = LLVMConstInt(LLVMInt32Type(), tab, false);
	assert(llvm_tab_imm);
	llvm_tab_store = curr_col_ref_meta.llvm_tab_store =
	LLVMBuildStore(b, llvm_tab_imm, llvm_tab_var);
	assert(llvm_tab_store);
	llvm_tab_var = LLVMBuildLoad2(b, LLVMInt32Type(), llvm_tab_var, "");
	llvm_col_var = curr_col_ref_meta.llvm_col_var =
		LLVMBuildAlloca(b, LLVMInt32Type(), "col");
	assert(llvm_col_var);
	llvm_col_imm = LLVMConstInt(LLVMInt32Type(), col, false);
	assert(llvm_col_imm);
	llvm_col_store = curr_col_ref_meta.llvm_col_store =
	LLVMBuildStore(b, llvm_col_imm, llvm_col_var);
	assert(llvm_col_store);
	llvm_col_var = LLVMBuildLoad2(b, LLVMInt32Type(), llvm_col_var, "");
	curr_col_ref_meta.tgt_reg_idx = tgt_reg_idx;
	llvm_fn = llvm_get_fn(m, llvm_vdbe_op_column);
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	llvm_fn_args[0] = llvm_vdbe;
	llvm_fn_args[1] = llvm_tab_var;
	llvm_fn_args[2] = llvm_col_var;
	llvm_fn_args[3] = llvm_tgt_reg_idx;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				 llvm_fn_args_cnt, "rc");
	assert(llvm_rc);
	llvm_build_rc_check(ctx, llvm_rc);
	curr_bb = LLVMGetInsertBlock(b);
	op_col_end_bb = curr_col_ref_meta.bb_end =
	LLVMCreateBasicBlockInContext(m_ctx, "OP_Column_end");
	assert(op_col_end_bb);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, op_col_end_bb);
	LLVMBuildBr(b, op_col_end_bb);
	LLVMPositionBuilderAtEnd(b, op_col_end_bb);
	if (!expr->op2)
		sqlExprCacheStore(parse_ctx, tab, col, tgt_reg_idx);
	col_ref_meta_cnt = ctx->col_ref_meta_cnt;
	assert(col_ref_meta_cnt >= 0);
	col_ref_meta = ctx->col_ref_meta;
	if (!col_ref_meta_cnt) {
		assert(!col_ref_meta);
		region = &parse_ctx->region;
		col_ref_meta = region_alloc_array(region,
						  typeof(struct llvm_col_ref_meta),
						  1, &col_ref_meta_sz);
		if (!col_ref_meta)
			goto region_alloc_err;
	} else if (IsPowerOfTwo(col_ref_meta_cnt)) {
		assert(col_ref_meta);
		region = &parse_ctx->region;
		col_ref_meta = region_alloc_array(region,
						  typeof(struct llvm_col_ref_meta),
						  col_ref_meta_cnt << 1,
						  &col_ref_meta_sz);
		if (!col_ref_meta)
			goto region_alloc_err;
		memcpy(col_ref_meta, ctx->col_ref_meta,
		       col_ref_meta_cnt * sizeof(struct llvm_col_ref_meta));
		/*
		 * FIXME: is it okay that we do not clean up previously
		 * allocated memory?
		 */
	}
	if (col_ref_meta != ctx->col_ref_meta) {
		assert(col_ref_meta);
		ctx->col_ref_meta = col_ref_meta;
	}
	col_ref_meta[ctx->col_ref_meta_cnt++] = curr_col_ref_meta;
	return true;

	region_alloc_err:
	diag_set(OutOfMemory, col_ref_meta_sz, "region_alloc_array",
		 "struct col_ref_meta");
	parse_ctx->is_aborted = true;
	return false;
}

static void
llvm_build_mem_copy(struct llvm_build_ctx *ctx, int src_reg_idx,
		    int tgt_reg_idx)
{
	assert(ctx);
	assert(src_reg_idx >= 0);
	assert(tgt_reg_idx >= 0);

	LLVMModuleRef m;
	LLVMBuilderRef b;
	LLVMValueRef llvm_src_reg_idx;
	LLVMValueRef llvm_src_reg;
	LLVMValueRef llvm_tgt_reg_idx;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_regs;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[2];
	unsigned int llvm_fn_args_cnt;
	LLVMValueRef llvm_rc;
	const char *name;

	m = ctx->module;
	assert(m);
	b = ctx->builder;
	assert(b);
	llvm_regs = ctx->llvm_regs;
	assert(llvm_regs);
	llvm_src_reg_idx = LLVMConstInt(LLVMInt32Type(), src_reg_idx, false);
	assert(llvm_src_reg_idx);
	name = tt_sprintf("src_reg");
	assert(name);
	llvm_src_reg = LLVMBuildInBoundsGEP2(b, llvm_mem_type, llvm_regs,
					     &llvm_src_reg_idx, 1, name);
	assert(llvm_src_reg);
	llvm_tgt_reg_idx = LLVMConstInt(LLVMInt32Type(), tgt_reg_idx, false);
	assert(llvm_tgt_reg_idx);
	name = tt_sprintf("tgt_reg");
	assert(name);
	llvm_tgt_reg = LLVMBuildInBoundsGEP2(b, llvm_mem_type, llvm_regs,
					     &llvm_tgt_reg_idx, 1, name);
	assert(llvm_tgt_reg);
	/* FIXME: copy operation can depend on SQL_ECEL_DUP */
	llvm_fn = llvm_get_fn(m, llvm_mem_copy);
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args[1] = llvm_src_reg;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				 llvm_fn_args_cnt, "llvm_rc");
	assert(llvm_rc);
	llvm_build_rc_check(ctx, llvm_rc);
}

static void
llvm_build_rc_check(struct llvm_build_ctx *ctx, LLVMValueRef llvm_rc)
{
	assert(ctx);
	assert(llvm_rc);

	LLVMModuleRef m;
	LLVMContextRef m_ctx;
	LLVMBuilderRef b;
	LLVMBasicBlockRef curr_bb;
	LLVMBasicBlockRef err_bb;
	LLVMBasicBlockRef ok_bb;
	LLVMValueRef llvm_if;
	LLVMValueRef llvm_false;
	LLVMValueRef llvm_ok;

	m = ctx->module;
	assert(m);
	m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx);
	b = ctx->builder;
	assert(b);
	curr_bb = LLVMGetInsertBlock(b);
	assert(curr_bb);
	err_bb = LLVMCreateBasicBlockInContext(m_ctx, "err");
	assert(err_bb);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, err_bb);
	LLVMPositionBuilderAtEnd(b, err_bb);
	llvm_false = LLVMConstInt(LLVMInt1Type(), false, false);
	assert(llvm_false);
	ALWAYS(LLVMBuildRet(b, llvm_false));
	ok_bb = LLVMCreateBasicBlockInContext(m_ctx, "ok");
	assert(ok_bb);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, ok_bb);
	LLVMPositionBuilderAtEnd(b, curr_bb);
	llvm_ok = LLVMConstInt(LLVMInt32Type(), 0, false);
	assert(llvm_ok);
	llvm_if = LLVMBuildICmp(b, LLVMIntNE, llvm_rc, llvm_ok, "cond");
	assert(llvm_if);
	ALWAYS(LLVMBuildCondBr(b, llvm_if, err_bb, ok_bb));
	LLVMPositionBuilderAtEnd(b, ok_bb);
}