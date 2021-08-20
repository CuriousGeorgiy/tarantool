/*
 * Copyright 2021, Tarantool AUTHORS, please see AUTHORS file.
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

#include "llvm-c/Transforms/AggressiveInstCombine.h"
#include "llvm-c/Transforms/IPO.h"
#include "llvm-c/Transforms/PassManagerBuilder.h"
#include "llvm-c/Transforms/Scalar.h"
#include "llvm-c/Transforms/Utils.h"

/**
 * This part of the build context remains persistent for the whole construction
 * process.
 */
static const size_t llvm_build_ctx_ini_sz =
	offsetof(struct llvm_build_ctx, cb_id);

/** Used for callback function unique name generation. */
static const char *const fn_name_prefix = "cb_";
/** Name of module in which callback functions are built. */
static const char *const module_name = "sql_vdbe";
/** Name of file to which module contents are printed. */
static const char *const module_file_name = "sql_vdbe.ll";

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
/* FIXME: should be disposed sometime, e.g. after session shutdown? */

/**
 * Module containing type definitions and auxiliary function
 * declarations.
 */
static LLVMModuleRef llvm_bootstrap_module;

/**
 * Create the base module from an embedded LLVM bitcode string, populate the
 * type and auxiliary function references.
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

/**
 * Create function declaration in module, if it does not yet exist, return
 * function reference from the module.
 */
static LLVMValueRef
llvm_get_fn(LLVMModuleRef m, LLVMValueRef extern_fn);

/** Callback function passed to LLVMOrcExecutionSessionSetErrorReporter. */
static void
llvm_log_jit_error(void *unused, LLVMErrorRef err);

/** Perform set of lightweight IR optimizations on module. */
static void
llvm_optimize_module(LLVMModuleRef m);

/** Add the current module to LLJIT and compile it. */
static bool
llvm_lljit_compile_module(struct llvm_jit_ctx *jit_ctx);

/** Lookup a callback in LLJIT. */
static LLVMOrcJITTargetAddress
llvm_lljit_lookup_cb(struct llvm_jit_ctx *ctx, int cb_id);

/**
 * Initialize llvm_build_ctx, build new callback function's entry block
 * and build a local variable to access Vdbe->aMem.
 */
static void
llvm_build_cb_ini(struct llvm_jit_ctx *jit_ctx);

/**
 * Build callback function's return status and set non-consistent part
 * of llvm_build_ctx to zero.
 */
static bool
llvm_build_cb_fin(struct llvm_build_ctx *build_ctx);

/**
 * Initialize the llvm_build_ctx state, build sql_context's for each aggregate
 * function in query.
 */
static bool
llvm_build_agg_loop_ini(struct llvm_jit_ctx *jit_ctx, AggInfo *agg_info);

/**
 * Build expression lists of aggregate function arguments and
 * aggregate function steps.
 */
static bool
llvm_build_agg_loop_body(struct llvm_jit_ctx *jit_ctx, AggInfo *agg_info);

/**
 * Build loop ending and sql_context's cleanup, finalize the llvm_build_ctx
 * state.
 */
static bool
llvm_build_agg_loop_fin(struct llvm_build_ctx *build_ctx, WhereLevel *where_lvl,
			AggInfo *agg_info);

/** Initialize the llvm_build_ctx state. */
static void
llvm_build_expr_list_ini(struct llvm_jit_ctx *jit_ctx, int src_regs_idx,
			 int tgt_regs_idx);

/** Build expression list item. */
static bool
llvm_build_expr_list_item(struct llvm_jit_ctx *jit_ctx,
			  struct ExprList_item *item, int expr_idx,
			  int flags);

/** Finalize the llvm_build_ctx state. */
static bool
llvm_build_expr_list_fin(struct llvm_jit_ctx *jit_ctx);

/** Build the current expression. */
static bool
llvm_build_expr(struct llvm_build_ctx *ctx);

/** Build aggregate column expression. */
static bool
llvm_build_agg_column(struct llvm_build_ctx *ctx);

/** Build column reference expression. */
static bool
llvm_build_col_ref(struct llvm_build_ctx *build_ctx);

/** Build integer expression. */
static bool
llvm_build_int(struct llvm_build_ctx *ctx, bool is_neg);

/** Build boolean expression. */
static void
llvm_build_bool(struct llvm_build_ctx *ctx);

/** Build double precision floating point expression. */
static bool
llvm_build_double(struct llvm_build_ctx *ctx, bool is_neg);

/** Build null-terminated string expression. */
static bool
llvm_build_str(struct llvm_build_ctx *build_ctx);

/** Build null expression. */
static void
llvm_build_null(struct llvm_build_ctx *ctx);

/** Build call to vdbe_op_column and check its return code. */
static bool
llvm_build_vdbe_op_column(struct llvm_build_ctx *ctx, int tab, int col);

/** Build call to mem_copy and check its return code. */
static void
llvm_build_mem_copy(struct llvm_build_ctx *ctx, int src_reg_idx,
		    int dst_reg_idx);

/** Build return code check. */
static void
llvm_build_rc_check(struct llvm_build_ctx *ctx, LLVMValueRef llvm_rc);

bool
llvm_session_init(void)
{
	sql *sql = sql_get();
	assert(sql != NULL);
	LLVMPassRegistryRef llvm_gl_pass_reg = LLVMGetGlobalPassRegistry();
	assert(llvm_gl_pass_reg != NULL);
	LLVMContextRef llvm_gl_ctx= LLVMGetGlobalContext();
	assert(llvm_gl_ctx != NULL);
	const char *llvm_triple;
	LLVMTargetRef llvm_t;
	LLVMTargetMachineRef default_tm;
	char *err_msg;
	char *cpu_name = LLVMGetHostCPUName();
	assert(cpu_name != NULL);;
	char *cpu_feats = LLVMGetHostCPUFeatures();
	assert(cpu_feats != NULL);

	assert(!sql->llvm_session_ini);
	LLVMInitializeCore(llvm_gl_pass_reg);
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
	assert(llvm_triple != NULL);
	if (LLVMGetTargetFromTriple(llvm_triple, &llvm_t, &err_msg) != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to get target from triple: %s", err_msg);
		LLVMDisposeErrorMessage(err_msg);
		err_msg = NULL;
		return false;
	}
	if (LLVMTargetHasJIT(llvm_t) == 0) {
		/* FIXME: move to diag_set */
		say_error("target machine does not support JIT: please, "
			  "turn JIT option off");
		return true;
	}
	say_info("LLVMJIT detected CPU '%s', with features '%s'",
		 cpu_name, cpu_feats);
	default_tm = LLVMCreateTargetMachine(llvm_t, llvm_triple,
					     cpu_name, cpu_feats,
					     LLVMCodeGenLevelAggressive,
					     LLVMRelocDefault,
					     LLVMCodeModelJITDefault);
	assert(default_tm != NULL);
	LLVMDisposeMessage(cpu_name);
	cpu_name = NULL;
	LLVMDisposeMessage(cpu_feats);
	cpu_feats = NULL;
	if (!llvm_lljit_inst_create(default_tm))
		return false;
	sql->llvm_session_ini = true;
	return true;
}

struct llvm_jit_ctx *
llvm_jit_ctx_new(Parse *parse_ctx)
{
	assert(parse_ctx != NULL);

	size_t jit_ctx_sz = sizeof(struct llvm_jit_ctx);;
	struct llvm_jit_ctx *jit_ctx;
	LLVMContextRef llvm_m_ctx;
	/* FIXME: should use a thread-safe context instead of a global one? */
	LLVMModuleRef m = LLVMModuleCreateWithName(module_name);
	assert(m != NULL);
	size_t build_ctx_sz = sizeof(struct llvm_build_ctx);
	struct llvm_build_ctx *build_ctx;

	jit_ctx = sqlMalloc(jit_ctx_sz);
	if (jit_ctx == NULL) {
		diag_set(OutOfMemory, jit_ctx_sz, "sqlMalloc",
			 "struct llvm_jit_ctx");
		return NULL;
	}
	jit_ctx->module = m;
	llvm_m_ctx = LLVMGetModuleContext(m);
	assert(llvm_m_ctx != NULL);
	LLVMContextSetDiagnosticHandler(llvm_m_ctx, llvm_diag_handler, NULL);
	jit_ctx->rt = NULL;
	build_ctx = jit_ctx->build_ctx =
		region_alloc(&parse_ctx->region, build_ctx_sz);
	if (build_ctx == NULL) {
		diag_set(OutOfMemory, build_ctx_sz, "region_alloc",
			 "struct llvm_build_ctx");
		return NULL;
	}
	build_ctx->module = m;
	build_ctx->builder = LLVMCreateBuilder();
	build_ctx->parse_ctx = parse_ctx;
	memset((char *)build_ctx + llvm_build_ctx_ini_sz, 0,
	       build_ctx_sz - llvm_build_ctx_ini_sz);
	jit_ctx->cb_cnt = 0;
	return jit_ctx;
}

void
llvm_jit_ctx_delete(struct llvm_jit_ctx *jit_ctx)
{
	LLVMModuleRef m;
	struct llvm_build_ctx *build_ctx;
	LLVMOrcResourceTrackerRef rt;
	LLVMOrcExecutionSessionRef es;
	LLVMOrcSymbolStringPoolRef ssp;
	LLVMErrorRef err;

	if (jit_ctx == NULL)
		return;
	m = jit_ctx->module;
	if (m != NULL) {
		LLVMDisposeModule(m);
		jit_ctx->module = NULL;
	}
	build_ctx = jit_ctx->build_ctx;
	if (build_ctx != NULL) {
		LLVMBuilderRef b = build_ctx->builder;
		assert(b != NULL);

		LLVMDisposeBuilder(b);
		build_ctx->builder = NULL;
		jit_ctx->build_ctx = NULL;
	}
	rt = jit_ctx->rt;
	if (rt != NULL) {
		err = LLVMOrcResourceTrackerRemove(rt);
		if (err != NULL) {
			const char *err_msg = llvm_get_err_msg(err);
			assert(err_msg != NULL);

			/* FIXME: move to diag_set */
			say_error("failed to remove resource tracker: %s",
				  err_msg);
			/* FIXME: should return status? */
			return;
		}
		LLVMOrcReleaseResourceTracker(rt);
	}
	es = LLVMOrcLLJITGetExecutionSession(llvm_lljit);
	assert(es != NULL);
	ssp = LLVMOrcExecutionSessionGetSymbolStringPool(es);
	assert(ssp != NULL);
	LLVMOrcSymbolStringPoolClearDeadEntries(ssp);
	sql_free(jit_ctx);
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
	int cb_id;
	int col_ref_meta_cnt;
	struct llvm_col_ref_meta *col_ref_meta;

	if (!llvm_build_agg_loop_ini(jit_ctx, agg_info))
		return false;
	if (!llvm_build_agg_loop_body(jit_ctx, agg_info))
		return false;
	cb_id = build_ctx->cb_id;
	assert(cb_id >= 0);
	col_ref_meta_cnt = build_ctx->col_ref_meta_cnt;
	assert(col_ref_meta_cnt >= 0);
	col_ref_meta = build_ctx->col_ref_meta;
	assert(col_ref_meta == 0 || col_ref_meta != 0);
	llvm_build_agg_loop_fin(build_ctx, where_lvl, agg_info);
	sqlVdbeAddOp4(vdbe, OP_ExecJITCallback, cb_id, col_ref_meta_cnt, 0,
		      (const char *)col_ref_meta, P4_PTR);
	VdbeComment((vdbe, "Callback for evaluating aggregate query"));
	sqlVdbeResolveLabel(vdbe, where_lvl->addrBrk);
	sqlVdbeResolveLabel(vdbe, where_info->iBreak);
	sqlWherePostEnd(where_info);
	return true;
}

bool
llvm_build_expr_list(struct llvm_jit_ctx *jit_ctx, Parse *parse_ctx,
		     ExprList *expr_list, int *expr_cnt, int src_regs_idx,
		     int tgt_regs_idx, u8 flags)
{
	assert(jit_ctx != NULL);
	assert(parse_ctx != NULL);
	assert(expr_list != NULL);
	assert(expr_cnt != NULL);
	assert(*expr_cnt > 0);
	assert(src_regs_idx >= 0);
	assert(tgt_regs_idx > 0);

	int i;
	struct ExprList_item *item;
	struct llvm_build_ctx *build_ctx;
	int cb_id;
	int col_ref_meta_cnt;
	struct llvm_col_ref_meta *col_ref_meta;
	Vdbe *vdbe = parse_ctx->pVdbe;
	assert(vdbe != NULL);

	llvm_build_expr_list_ini(jit_ctx, src_regs_idx, tgt_regs_idx);
	assert(expr_cnt == 0 || expr_list->a != NULL);
	for (i = 0, item = expr_list->a; i < *expr_cnt; ++i, ++item) {
		Expr *expr = item->pExpr;
		assert(expr);
		int j;

		if ((flags & SQL_ECEL_REF) != 0 &&
		    (flags & SQL_ECEL_OMITREF) != 0 &&
		    (j = item->u.x.iOrderByCol) != 0) {
			--i;
			--*expr_cnt;
		} else if ((flags & SQL_ECEL_FACTOR) != 0 &&
			   sqlExprIsConstant(item->pExpr)) {
			int tgt_reg_idx = tgt_regs_idx + i;

			sqlExprCodeAtInit(parse_ctx, expr, tgt_reg_idx, 0);
		} else {
			if (!llvm_build_expr_list_item(jit_ctx, item, i, flags)) {
				parse_ctx->is_aborted = true;
				return false;
			}
		}
	}
	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	cb_id = build_ctx->cb_id;
	assert(cb_id >= 0);
	col_ref_meta = build_ctx->col_ref_meta;
	col_ref_meta_cnt = build_ctx->col_ref_meta_cnt;
	assert(col_ref_meta_cnt >= 0);
	assert(!col_ref_meta_cnt || col_ref_meta);
	if (!llvm_build_expr_list_fin(jit_ctx)) {
		parse_ctx->is_aborted = true;
		return false;
	}
	sqlVdbeAddOp4(vdbe, OP_ExecJITCallback, cb_id, col_ref_meta_cnt,
		      0, (const char *)col_ref_meta, P4_PTR);
	VdbeComment((vdbe, "Callback for pushing result set expression list"));
	return true;
}

bool
llvm_exec_compiled_cb(struct llvm_jit_ctx *ctx, int cb_id, Vdbe *vdbe)
{
	assert(ctx != NULL);
	assert(cb_id >= 0);
	assert(vdbe != NULL);

	LLVMOrcJITTargetAddress fn_addr = llvm_lljit_lookup_cb(ctx, cb_id);
	assert(fn_addr != 0);

	return ((bool (*) (Vdbe *))fn_addr)(vdbe);
}

bool
llvm_jit_ctx_fin(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx != NULL);

	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
#ifdef SQL_DEBUG
	LLVMModuleRef m = build_ctx->module;
	assert(m != NULL);
	char *err_msg;
#endif

	LLVMDisposeBuilder(b);
	build_ctx->builder = NULL;
	jit_ctx->build_ctx = NULL;
#ifdef SQL_DEBUG
	if (LLVMPrintModuleToFile(m, module_file_name, &err_msg) != 0) {
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
#endif
	if (!build_ctx->module_empty)
		return llvm_lljit_compile_module(jit_ctx);
	return true;
}

void
llvm_jit_change_col_refs_to_reg_copies(struct llvm_jit_ctx *jit_ctx,
				       struct llvm_col_ref_meta *col_ref_meta,
				       int col_ref_meta_cnt, int tab,
				       int coro_src_regs_idx)
{
	assert(jit_ctx != NULL);
	assert(col_ref_meta_cnt >= 0);
	assert(tab >= 0);
	assert(coro_src_regs_idx >= 0);

	int i;
	struct llvm_col_ref_meta *p;

	assert(col_ref_meta_cnt == 0 || col_ref_meta != NULL);
	for (i = 0, p = col_ref_meta; i < col_ref_meta_cnt; ++i, ++p) {
		LLVMBasicBlockRef op_col_begin_bb;
		LLVMBasicBlockRef pred_bb;
		LLVMValueRef br_instr;
		struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
		assert(build_ctx != NULL);
		LLVMBuilderRef b = build_ctx->builder;
		assert(b != NULL);
		LLVMValueRef llvm_cb = build_ctx->llvm_cb = p->llvm_cb;
		assert(llvm_cb != NULL);
		LLVMBasicBlockRef op_col_end_bb;
		LLVMBasicBlockRef bb;
		LLVMValueRef op_col_end_bb_val;
		int col = p->col;
		assert(col >= 0);
		int coro_src_reg_idx = coro_src_regs_idx + col;
		int tgt_reg_idx = p->tgt_reg_idx;
		assert(tgt_reg_idx > 0);
		LLVMValueRef llvm_regs = build_ctx->llvm_regs = p->llvm_regs;
		assert(llvm_regs != NULL);

		if (p->tab != tab)
			continue;
		op_col_begin_bb = p->bb_begin;
		assert(op_col_begin_bb != NULL);
		pred_bb = LLVMGetPreviousBasicBlock(op_col_begin_bb);
		assert(pred_bb != NULL);
		br_instr = LLVMGetLastInstruction(pred_bb);
		assert(br_instr != NULL);
		assert(LLVMIsABranchInst(br_instr) != NULL);
		LLVMInstructionEraseFromParent(br_instr);
		br_instr = NULL;
		LLVMPositionBuilderAtEnd(b, pred_bb);
		op_col_end_bb = p->bb_end;
		assert(op_col_end_bb != NULL);
		assert(op_col_begin_bb != op_col_end_bb);
		bb = LLVMGetPreviousBasicBlock(op_col_begin_bb);
		assert(bb != NULL);
		pred_bb = NULL;
		do {
			bb = LLVMGetNextBasicBlock(bb);
			assert(bb != NULL);
			if (pred_bb != NULL)
				LLVMDeleteBasicBlock(pred_bb);
			pred_bb = bb;
		} while (bb != op_col_end_bb);
		p->bb_begin = NULL;
		p->bb_end = NULL;
		op_col_end_bb_val = LLVMBasicBlockAsValue(op_col_end_bb);
		assert(op_col_end_bb_val != NULL);
		LLVMSetValueName2(op_col_end_bb_val, "aux", strlen("aux"));
		llvm_build_mem_copy(build_ctx, coro_src_reg_idx, tgt_reg_idx);
		ALWAYS(LLVMBuildBr(b, op_col_end_bb) != NULL);
	}
}

void
llvm_jit_patch_idx_col_refs(struct llvm_jit_ctx *jit_ctx, WhereLevel *where_lvl,
			    struct index_def *idx_def,
			    struct llvm_col_ref_meta *col_ref_meta,
			    int col_ref_meta_cnt)
{
	assert(jit_ctx != NULL);
	assert(where_lvl != NULL);
	assert(idx_def != NULL);

	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
	WhereLoop *where_loop = where_lvl->pWLoop;
	assert(where_loop != NULL);
	int curr_tab = where_lvl->iTabCur;
	assert(curr_tab >= 0);
	int curr_idx = where_lvl->iIdxCur;
	assert(curr_idx >= 0);
	int i;
	struct llvm_col_ref_meta *p;

	assert(col_ref_meta_cnt == 0 || col_ref_meta != NULL);
	for (i = 0, p = col_ref_meta; i < col_ref_meta_cnt; ++i, ++p) {
		int tab = p->tab;
		assert(tab >= 0);
		LLVMValueRef llvm_idx =
			LLVMConstInt(LLVMInt32Type(), curr_idx, false);
		assert(llvm_idx != NULL);
		LLVMValueRef llvm_tab_var = p->llvm_tab_var;
		assert(llvm_tab_var != NULL);
		LLVMValueRef llvm_tab_store = p->llvm_tab_store;
		assert(llvm_tab_store != NULL);
		LLVMBasicBlockRef bb;
		struct key_def *key_def = idx_def->key_def;
		assert(key_def != NULL);
		uint32_t part_cnt = key_def->part_count;
		uint32_t j;
		struct key_part *key_part;

		if (tab != curr_tab)
			continue;
		p->tab = curr_idx;
		bb = p->bb_begin;
		assert(bb != NULL);
		LLVMPositionBuilder(b, bb, llvm_tab_store);
		p->llvm_tab_store = LLVMBuildStore(b, llvm_idx, llvm_tab_var);
		assert(p->llvm_tab_store != NULL);
		LLVMInstructionEraseFromParent(llvm_tab_store);
		llvm_tab_store = NULL;
		if ((where_loop->wsFlags & WHERE_AUTO_INDEX) == 0)
			continue;
		assert(key_def->parts != NULL);
		for (j = 0, key_part = key_def->parts; j < part_cnt; ++j, ++key_part) {
			int col = p->col;
			assert(col >= 0);

			if (key_part->fieldno == (uint32_t)col) {
				LLVMValueRef llvm_eph_idx_col =
					LLVMConstInt(LLVMInt32Type(), j, false);
				assert(llvm_eph_idx_col != NULL);
				LLVMValueRef llvm_col_var = p->llvm_col_var;
				assert(llvm_col_var != NULL);
				LLVMValueRef llvm_col_store = p->llvm_col_store;
				assert(llvm_col_store != NULL);

				p->col = (int)j;
				LLVMPositionBuilder(b, bb, llvm_col_store);
				p->llvm_col_store =
					LLVMBuildStore(b, llvm_eph_idx_col,
						       llvm_col_var);
				assert(p->llvm_col_store != NULL);
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
	size_t len = lengthof(llvm_jit_bootstrap_bin);
	LLVMMemoryBufferRef buf =
		LLVMCreateMemoryBufferWithMemoryRange((const char *)llvm_jit_bootstrap_bin,
						      len, NULL, false);
	assert(buf != NULL);
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

	if (LLVMParseBitcode2(buf, &llvm_bootstrap_module) != 0) {
		/* FIXME: move to diag_set */
		say_error("parsing of LLVM bitcode failed");
		return false;
	}
	LLVMDisposeMemoryBuffer(buf);
	buf = NULL;
	m = llvm_bootstrap_module;
	assert(m != NULL);
	m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx != NULL);
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

static void
llvm_diag_handler(LLVMDiagnosticInfoRef di, void *unused) {
	assert(di != NULL);
	(void)unused;

	const char *diag_info_descr = LLVMGetDiagInfoDescription(di);
	assert(diag_info_descr != NULL);

	/* FIXME: move to diag_set */
	say_error("error occurred during JIT'ing: %s", diag_info_descr);
}

static LLVMOrcObjectLayerRef
llvm_obj_linking_layer_create(void *unused1, LLVMOrcExecutionSessionRef es,
			      const char *unused2)
{
	(void)unused1;
	(void)unused2;

	LLVMOrcObjectLayerRef ol =
		LLVMOrcCreateRTDyldObjectLinkingLayerWithSectionMemoryManager(es);
	assert(ol != NULL);
	return ol;
}

static LLVMValueRef
llvm_get_fn(LLVMModuleRef m, LLVMValueRef extern_fn)
{
	assert(m != NULL);
	assert(extern_fn != NULL);

	size_t unused;
	const char *fn_name = LLVMGetValueName2(extern_fn, &unused);
	assert(fn_name != NULL);
	LLVMValueRef internal_fn = LLVMGetNamedFunction(m, fn_name);
	LLVMTypeRef fn_type;

	if (internal_fn != NULL)
		return internal_fn;
	fn_type = LLVMGetElementType(LLVMTypeOf(extern_fn));
	assert(fn_type != NULL);
	internal_fn = LLVMAddFunction(m, fn_name, fn_type);
	assert(internal_fn != NULL);
	return internal_fn;
}

static void
llvm_log_jit_error(void *unused, LLVMErrorRef err)
{
	(void)unused;
	assert(err != NULL);

	const char *err_msg = llvm_get_err_msg(err);
	assert(err_msg != NULL);

	/* FIXME: move to diag_set */
	say_error("error occurred during JIT'ing: %s", err_msg);
}

static const char *
llvm_get_err_msg(LLVMErrorRef err)
{
	assert(err != NULL);

	char *orig = LLVMGetErrorMessage(err);
	assert(orig != NULL);
	const char *cp = tt_cstr(orig, strlen(orig));
	assert(cp != NULL);

	LLVMDisposeErrorMessage(orig);
	orig = NULL;
	return cp;
}

static bool
llvm_lljit_inst_create(LLVMTargetMachineRef tm)
{
	assert(tm != NULL);

	LLVMOrcLLJITBuilderRef lljit_builder = LLVMOrcCreateLLJITBuilder();
	assert(lljit_builder != NULL);
	LLVMOrcJITTargetMachineBuilderRef jtmb =
		LLVMOrcJITTargetMachineBuilderCreateFromTargetMachine(tm);
	assert(jtmb != NULL);
	LLVMErrorRef err;
	const char *err_msg;
	LLVMOrcExecutionSessionRef es;
	char lljit_gl_prefix;
	LLVMOrcDefinitionGeneratorRef dg;
	LLVMOrcJITDylibRef jd;

	LLVMOrcLLJITBuilderSetJITTargetMachineBuilder(lljit_builder, jtmb);
	LLVMOrcLLJITBuilderSetObjectLinkingLayerCreator(lljit_builder,
							llvm_obj_linking_layer_create,
							NULL);
	err = LLVMOrcCreateLLJIT(&llvm_lljit, lljit_builder);
	if (err != NULL) {
		err_msg = llvm_get_err_msg(err);
		assert(err_msg != NULL);
		/* FIXME: move to diag_set */
		say_error("failed to create LLJIT instance: %s", err_msg);
		return false;
	}
	assert(llvm_lljit != NULL);
	es = LLVMOrcLLJITGetExecutionSession(llvm_lljit);
	assert(es != NULL);
	LLVMOrcExecutionSessionSetErrorReporter(es, llvm_log_jit_error, NULL);
	/*
	 * Symbol resolution support for symbols in the tarantool binary.
	 */
	lljit_gl_prefix = LLVMOrcLLJITGetGlobalPrefix(llvm_lljit);
	err = LLVMOrcCreateDynamicLibrarySearchGeneratorForProcess(&dg,
								   lljit_gl_prefix,
								   NULL, NULL);
	if (err != NULL) {
		err_msg = llvm_get_err_msg(err);
		assert(err_msg != NULL);
		/* FIXME: move to diag_set */
		say_error("failed to create generator: %s", err_msg);
		return false;
	}
	jd = LLVMOrcLLJITGetMainJITDylib(llvm_lljit);
	assert(jd != NULL);
	LLVMOrcJITDylibAddGenerator(jd, dg);
	return true;
}

static void
llvm_optimize_module(LLVMModuleRef m)
{
	assert(m != NULL);

	LLVMPassManagerBuilderRef pmb =  LLVMPassManagerBuilderCreate();
	assert(pmb != NULL);
	/* Function level optimizations. */
	LLVMPassManagerRef fpm = LLVMCreateFunctionPassManagerForModule(m);
	assert(fpm != NULL);
	LLVMValueRef llvm_fn;

	LLVMPassManagerBuilderSetOptLevel(pmb, 3);
	LLVMAddAggressiveInstCombinerPass(fpm);
	LLVMAddUnifyFunctionExitNodesPass(fpm);
	LLVMAddLowerSwitchPass(fpm);
	LLVMAddPromoteMemoryToRegisterPass(fpm);
	LLVMPassManagerBuilderPopulateFunctionPassManager(pmb, fpm);
	LLVMInitializeFunctionPassManager(fpm);
	for (llvm_fn = LLVMGetFirstFunction(m); llvm_fn != NULL; llvm_fn = LLVMGetNextFunction(llvm_fn))
		LLVMRunFunctionPassManager(fpm, llvm_fn);
	LLVMFinalizeFunctionPassManager(fpm) ;
	LLVMDisposePassManager(fpm);
	LLVMPassManagerBuilderDispose(pmb);
}

static bool
llvm_lljit_compile_module(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx != NULL);

	LLVMModuleRef m = jit_ctx->module;
	assert(m != NULL);
	LLVMOrcThreadSafeContextRef llvm_ts_ctx =
		LLVMOrcCreateNewThreadSafeContext();
	assert(llvm_ts_ctx != NULL);
	LLVMOrcThreadSafeModuleRef tsm =
		LLVMOrcCreateNewThreadSafeModule(m, llvm_ts_ctx);
	assert(tsm != NULL);
	assert(llvm_lljit != NULL);
	LLVMOrcJITDylibRef jd = LLVMOrcLLJITGetMainJITDylib(llvm_lljit);
	assert(jd != NULL);
	LLVMOrcResourceTrackerRef rt = jit_ctx->rt =
		LLVMOrcJITDylibCreateResourceTracker(jd);
	assert(rt != NULL);
	LLVMErrorRef err;

	llvm_optimize_module(m);
	LLVMOrcDisposeThreadSafeContext(llvm_ts_ctx);
	jit_ctx->module = NULL; /* ownership transferred to thread-safe module */
	assert(llvm_lljit != NULL);
	/*
	 * NB: This does not actually compile code. That happens lazily the first
	 * time a symbol defined in the module is requested.
	 */
	err = LLVMOrcLLJITAddLLVMIRModuleWithRT(llvm_lljit, rt, tsm);
	if (err != NULL) {
		const char *err_msg = llvm_get_err_msg(err);
		assert(err_msg != NULL);

		diag_set(ClientError, ER_LLVM_IR_COMPILATION, err_msg);
		return false;
	}
	ALWAYS(llvm_lljit_lookup_cb(jit_ctx, 0) != 0);
	return true;
}

static LLVMOrcJITTargetAddress
llvm_lljit_lookup_cb(struct llvm_jit_ctx *ctx, int cb_id)
{
	assert(ctx != NULL);
	assert(cb_id >= 0);

	const char *fn_name = tt_sprintf("%s%d", fn_name_prefix, cb_id);
	assert(fn_name != NULL);
	LLVMOrcJITTargetAddress fn_addr;
	LLVMErrorRef err;

	assert(ctx->module == NULL);
	assert(llvm_lljit != NULL);
	err = LLVMOrcLLJITLookup(llvm_lljit, &fn_addr, fn_name);
	if (err != NULL) {
		const char *err_msg = llvm_get_err_msg(err);
		assert(err_msg != NULL);

		diag_set(ClientError, ER_LLVM_IR_COMPILATION, err_msg);
		return false;
	}
	assert(fn_addr != 0);
	return fn_addr;
}

static void
llvm_build_cb_ini(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx != NULL);

	LLVMModuleRef m = jit_ctx->module;
	assert(m != NULL);
	LLVMTargetDataRef td = LLVMGetModuleDataLayout(m);
	assert(td != NULL);
	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);
	int cb_id = build_ctx->cb_id = jit_ctx->cb_cnt++;
	assert(cb_id >= 0);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
	LLVMTypeRef llvm_fn_param_types[] = { llvm_vdbe_ptr_type };
	unsigned int llvm_fn_param_types_cnt = lengthof(llvm_fn_param_types);
	LLVMTypeRef llvm_fn_type =
		LLVMFunctionType(LLVMInt1Type(), llvm_fn_param_types,
				 llvm_fn_param_types_cnt, false);
	const char *fn_name = tt_sprintf("%s%d", fn_name_prefix, build_ctx->cb_id);
	assert(fn_name != NULL);
	LLVMValueRef llvm_cb = build_ctx->llvm_cb =
		LLVMAddFunction(m, fn_name, llvm_fn_type);
	assert(llvm_cb != NULL);
	LLVMBasicBlockRef entry_bb = LLVMAppendBasicBlock(llvm_cb, "entry");
	assert(entry_bb != NULL);
	LLVMValueRef llvm_vdbe = build_ctx->llvm_vdbe = LLVMGetParam(llvm_cb, 0);
	assert(llvm_vdbe != NULL);
	unsigned int vdbe_aMem_idx =
		LLVMElementAtOffset(td, llvm_vdbe_type, offsetof(Vdbe, aMem));
	LLVMValueRef llvm_regs_ptr;
	LLVMValueRef llvm_regs;

	LLVMSetLinkage(llvm_cb, LLVMExternalLinkage);
	LLVMSetVisibility(llvm_cb, LLVMDefaultVisibility);
	LLVMPositionBuilderAtEnd(b, entry_bb);
	llvm_regs_ptr = LLVMBuildStructGEP2(b, llvm_vdbe_type, llvm_vdbe,
					    vdbe_aMem_idx, "regs_ptr");
	assert(llvm_regs_ptr != NULL);
	llvm_regs = build_ctx->llvm_regs =
		LLVMBuildLoad2(b, llvm_mem_ptr_type, llvm_regs_ptr, "regs");
	assert(llvm_regs != NULL);
}

static bool
llvm_build_cb_fin(struct llvm_build_ctx *build_ctx)
{
	assert(build_ctx != NULL);

	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
	LLVMValueRef llvm_ok = LLVMConstInt(LLVMInt1Type(), true, false);
	assert(llvm_ok != NULL);
	LLVMValueRef llvm_cb = build_ctx->llvm_cb;
	assert(llvm_cb != NULL);
#ifdef SQL_DEBUG
	LLVMModuleRef m = build_ctx->module;
	assert(m != NULL);
	char *err_msg;
#endif

	ALWAYS(LLVMBuildRet(b, llvm_ok) != NULL);
	memset((char *)build_ctx + llvm_build_ctx_ini_sz, 0,
	       sizeof(struct llvm_build_ctx) - llvm_build_ctx_ini_sz);
#ifdef SQL_DEBUG
	if (LLVMPrintModuleToFile(m, module_file_name, &err_msg) != 0) {
		/* FIXME: move to diag_set */
		say_error("printing module to file failed: %s", err_msg);
		LLVMDisposeMessage(err_msg);
		err_msg = NULL;
		return false;
	}
	if (LLVMVerifyFunction(llvm_cb, LLVMPrintMessageAction) != 0) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "function IR verification failed");
		return false;
	}
#endif
	build_ctx->module_empty = false;
	return true;
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
	assert(b != NULL);
	Parse *parse_ctx = build_ctx->parse_ctx;
	assert(parse_ctx != NULL);
	struct region region = parse_ctx->region;;
	LLVMValueRef *llvm_sql_ctx;
	LLVMValueRef llvm_vdbe;
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

static bool
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
	LLVMValueRef llvm_rc;
	{
		LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_vdbe_op_next);
		assert(llvm_fn != NULL);
		LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
		assert(llvm_fn_type != NULL);
		LLVMValueRef llvm_fn_args[] =
		{ llvm_vdbe, llvm_csr, llvm_res, llvm_event_cntr };
		unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
		llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
					 llvm_fn_args_cnt, "rc");
	}
	LLVMBasicBlockRef loop_exit_bb =
		LLVMCreateBasicBlockInContext(m_ctx, "agg_loop_break");
	assert(loop_exit_bb != NULL);
	LLVMBasicBlockRef continue_bb =
		LLVMCreateBasicBlockInContext(m_ctx, "agg_loop_continue");
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
		LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_vdbe_op_aggfinal);
		assert(llvm_fn != NULL);
		LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
		assert(llvm_fn_type != NULL);
		LLVMValueRef llvm_fn_args[] = { llvm_vdbe, llvm_sql_ctx[i] };
		unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);

		ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				      llvm_fn_args_cnt, "") != NULL);
	}
	return llvm_build_cb_fin(build_ctx);
}

void
llvm_build_expr_list_ini(struct llvm_jit_ctx *jit_ctx, int src_regs_idx,
int tgt_regs_idx)
{
	assert(jit_ctx != NULL);
	assert(src_regs_idx >= 0);
	assert(tgt_regs_idx > 0);

	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);

	llvm_build_cb_ini(jit_ctx);
	build_ctx->src_regs_idx = src_regs_idx;
	build_ctx->tgt_regs_idx = tgt_regs_idx;
}

bool
llvm_build_expr_list_item(struct llvm_jit_ctx *jit_ctx,
struct ExprList_item *item, int expr_idx, int flags)
{
	assert(jit_ctx != NULL);
	assert(item != NULL);
	assert(expr_idx >= 0);

	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
	Expr *expr = build_ctx->expr = item->pExpr;
	assert(expr != NULL);
	int tgt_regs_idx = build_ctx->tgt_regs_idx;
	assert(tgt_regs_idx > 0);
	int tgt_reg_idx = build_ctx->tgt_reg_idx = tgt_regs_idx + expr_idx;
	LLVMValueRef llvm_tgt_reg_idx = build_ctx->llvm_tgt_reg_idx =
	LLVMConstInt(LLVMInt32Type(), tgt_reg_idx , false);
	assert(llvm_tgt_reg_idx != NULL);
	const char *name = tt_sprintf("tgt_reg_%d", expr_idx);
	assert(name != NULL);
	LLVMValueRef llvm_tgt_reg  = build_ctx->llvm_tgt_reg =
	LLVMBuildInBoundsGEP2(b, llvm_mem_type, build_ctx->llvm_regs,
			      &llvm_tgt_reg_idx, 1, name);
	assert(llvm_tgt_reg != NULL);
	int j;

	if ((flags & SQL_ECEL_REF) != 0 && (j = item->u.x.iOrderByCol) > 0) {
		assert((flags & SQL_ECEL_OMITREF) == 0);

		int src_regs_idx = build_ctx->src_regs_idx;
		assert(src_regs_idx >= 0);
		int src_reg_idx = src_regs_idx + j - 1;

		llvm_build_mem_copy(build_ctx, src_reg_idx, tgt_reg_idx);
		return true;
	}
	return llvm_build_expr(build_ctx);
}

bool
llvm_build_expr_list_fin(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx != NULL);

	struct llvm_build_ctx *build_ctx = jit_ctx->build_ctx;
	assert(build_ctx != NULL);

	return llvm_build_cb_fin(build_ctx);
}

static bool
llvm_build_expr(struct llvm_build_ctx *ctx)
{
	assert(ctx != NULL);

	Expr *expr = ctx->expr;
	assert(expr != NULL);
	int op = !expr ? TK_NULL : expr->op;

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
		return llvm_build_double(ctx, false);
	case TK_STRING:
		return llvm_build_str(ctx);
	case TK_NULL:
		llvm_build_null(ctx);
		return true;
	case TK_UPLUS:
		assert(expr->pLeft != NULL);
		assert(expr->pRight == NULL);
		ctx->expr = expr->pLeft;
		return llvm_build_expr(ctx);
	default:
		unreachable();
	}
}

static bool
llvm_build_agg_column(struct llvm_build_ctx *ctx)
{
	assert(ctx != NULL);

	Expr *expr = ctx->expr;
	assert(expr != NULL);
	AggInfo *agg_info = expr->pAggInfo;
	assert(agg_info != NULL);
	assert(expr->iAgg >= 0);
	struct AggInfo_col *col = &agg_info->aCol[expr->iAgg];

	if (agg_info->directMode == 0) {
		assert(col->iMem > 0);

		int tgt_reg_idx = ctx->tgt_reg_idx;
		assert(tgt_reg_idx > 0);

		if (col->iMem == tgt_reg_idx)
			return true;
		llvm_build_mem_copy(ctx, col->iMem, tgt_reg_idx);
		return true;
	} else if (agg_info->useSortingIdx != 0) {
		struct space_def *space_def = col->space_def;
		assert(space_def != NULL);

		assert(agg_info->sortingIdxPTab >= 0);
		assert(col->iSorterColumn >= 0);
		if (!llvm_build_vdbe_op_column(ctx, agg_info->sortingIdxPTab,
					       col->iSorterColumn))
			return false;
		if (space_def->fields[expr->iAgg].type == FIELD_TYPE_NUMBER) {
			LLVMValueRef llvm_vdbe = ctx->llvm_vdbe;
			assert(llvm_vdbe != NULL);
			LLVMValueRef llvm_tgt_reg_idx = ctx->llvm_tgt_reg_idx;
			assert(llvm_tgt_reg_idx != NULL);
			LLVMModuleRef m = ctx->module;
			assert(m != NULL);
			LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_vdbe_op_realify);
			assert(llvm_fn != NULL);
			LLVMTypeRef llvm_fn_type =
				LLVMGetElementType(LLVMTypeOf(llvm_fn));
			assert(llvm_fn_type != NULL);
			LLVMValueRef llvm_fn_args[] = { llvm_vdbe, llvm_tgt_reg_idx };
			unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
			LLVMBuilderRef b = ctx->builder;
			assert(b != NULL);

			ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn,
					      llvm_fn_args, llvm_fn_args_cnt,
					      "") != NULL);
			return true;
		}
		return true;
	}
	return llvm_build_col_ref(ctx);
}

static bool
llvm_build_col_ref(struct llvm_build_ctx *build_ctx)
{
	assert(build_ctx != NULL);

	LLVMModuleRef m = build_ctx->module;
	assert(m != NULL);
	LLVMContextRef m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx != NULL);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
	Expr *expr = build_ctx->expr;
	assert(expr != NULL);
	int tab = expr->iTable;
	int col = expr->iColumn;
	assert(col >= 0);
	Parse *parse_ctx = build_ctx->parse_ctx;
	assert(parse_ctx != NULL);
	LLVMValueRef llvm_tgt_reg = build_ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg != NULL);
	LLVMValueRef llvm_tgt_reg_idx = build_ctx->llvm_tgt_reg_idx;
	assert(llvm_tgt_reg_idx != NULL);
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	unsigned int llvm_fn_args_cnt;
	LLVMValueRef llvm_vdbe = build_ctx->llvm_vdbe;
	assert(llvm_vdbe != NULL);
	LLVMValueRef llvm_rc;
	int i;
	struct yColCache *p;

	if (tab < 0) {
		if (parse_ctx->vdbe_field_ref_reg > 0) {
			LLVMTargetDataRef td = LLVMGetModuleDataLayout(m);
			assert(td != NULL);
			int vdbe_field_ref_reg_idx = parse_ctx->vdbe_field_ref_reg;
			assert(vdbe_field_ref_reg_idx >= 0);
			LLVMValueRef llvm_vdbe_field_ref_reg_idx =
				LLVMConstInt(LLVMInt32Type(), vdbe_field_ref_reg_idx,
					     false);
			assert(llvm_vdbe_field_ref_reg_idx != NULL);
			LLVMValueRef llvm_field_idx =
				LLVMConstInt(LLVMInt32Type(), col, false);
			assert(llvm_field_idx != NULL);
			LLVMValueRef llvm_fn_args[] = {
				llvm_vdbe,
				llvm_vdbe_field_ref_reg_idx,
				llvm_field_idx,
				llvm_tgt_reg_idx
			};

			llvm_fn = llvm_get_fn(m, llvm_vdbe_op_fetch);
			assert(llvm_fn != NULL);
			llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
			assert(llvm_fn_type != NULL);
			llvm_fn_args_cnt = lengthof(llvm_fn_args);
			llvm_rc =
				LLVMBuildCall2(b, llvm_fn_type, llvm_fn,
					       llvm_fn_args, llvm_fn_args_cnt, "rc");
			assert(llvm_rc != NULL);
			llvm_build_rc_check(build_ctx, llvm_rc);
			return true;
		} else {
			tab = parse_ctx->iSelfTab;
		}
	}
	for (i = 0, p = parse_ctx->aColCache; i < parse_ctx->nColCache; ++i, ++p) {
		assert(p->iTable >= 0);
		assert(p->iColumn >= 0);
		if (p->iTable == tab && p->iColumn == col) {
			p->lru = parse_ctx->iCacheCnt++;
			assert(p->lru >= 0);
			assert(p->iReg > 0);

			LLVMValueRef llvm_regs = build_ctx->llvm_regs;
			assert(llvm_regs != NULL);
			assert(p->iReg > 0);
			LLVMValueRef llvm_idx =
				LLVMConstInt(LLVMInt64Type(), p->iReg, false);
			assert(llvm_idx != NULL);
			LLVMValueRef llvm_cached_column_reg =
				LLVMBuildInBoundsGEP2(b, llvm_mem_type,
						      llvm_regs, &llvm_idx, 1,
						      "cached_col_reg");
			assert(llvm_cached_column_reg != NULL);
			LLVMValueRef llvm_fn_args[] = {
				llvm_tgt_reg,
				llvm_cached_column_reg
			};

			sqlExprCachePinRegister(parse_ctx, p->iReg);
			llvm_fn = llvm_get_fn(m, llvm_mem_copy);
			assert(llvm_fn != NULL);
			llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
			assert(llvm_fn_type != NULL);
			llvm_fn_args_cnt = lengthof(llvm_fn_args);
			llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn,
						 llvm_fn_args, llvm_fn_args_cnt, "");
			assert(llvm_rc != NULL);
			llvm_build_rc_check(build_ctx, llvm_rc);
			return true;
		}
	}
	return llvm_build_vdbe_op_column(build_ctx, tab, col);
}

static bool
llvm_build_int(struct llvm_build_ctx *ctx, bool is_neg)
{
	assert(ctx != NULL);

	LLVMValueRef llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg != NULL);
	LLVMModuleRef m = ctx->module;
	assert(m != NULL);
	LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_mem_set_int);
	assert(llvm_fn != NULL);
	LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type != NULL);
	Expr *expr = ctx->expr;
	assert(expr != NULL);
	LLVMBuilderRef b = ctx->builder;
	assert(b != NULL);
	const char *sign;
	LLVMValueRef llvm_val;
	LLVMValueRef llvm_is_neg = LLVMConstInt(LLVMInt1Type(), is_neg, false);
	assert(llvm_is_neg != NULL);
	LLVMValueRef llvm_fn_args[3];
	unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
	const char *z;
	int64_t i64val;

	if ((expr->flags & EP_IntValue) != 0) {
		int i32val = expr->u.iValue;
		assert(i32val >= 0);

		if (is_neg)
			i32val = -i32val;
		llvm_val = LLVMConstInt(LLVMInt64Type(), i32val, is_neg);
		assert(llvm_val != NULL);
		llvm_fn_args[0] = llvm_tgt_reg;
		llvm_fn_args[1] = llvm_val;
		llvm_fn_args[2] = llvm_is_neg;
		ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				      lengthof(llvm_fn_args), "") != NULL);
		return true;
	}

	z = expr->u.zToken;
	assert(z != NULL);
	assert(!ExprHasProperty(expr, EP_IntValue));
	sign = is_neg ? "-" : "";
	if (z[0] == '0' && (z[1] == 'x' || z[1] == 'X')) {
		errno = 0;
		if (is_neg) {
			i64val = strtoll(z, NULL, 16);
		} else {
			/* FIXME: use unsigned integer instead of signed */
			i64val = strtoull(z, NULL, 16);
			/*
			 * FIXME: why is this comparison correct? I would
			 * expect it to be (uint64_t)i64val > INT64_MAX.
			 */
			if (i64val > INT64_MAX)
				goto int_overflow;
		}
		if (errno != 0) {
			diag_set(ClientError, ER_HEX_LITERAL_MAX, sign, z,
				 strlen(z) - 2, 16);
			return false;
		}
	} else {
		size_t len = strlen(z);
		bool unused;

		if (sql_atoi64(z, &i64val, &unused, len) != 0 ||
		    (!is_neg && (uint64_t) i64val > INT64_MAX)) {
int_overflow:
			diag_set(ClientError, ER_INT_LITERAL_MAX, sign, z);
			return false;
		}
	}
	if (is_neg)
		i64val = -i64val;
	llvm_val = LLVMConstInt(LLVMInt64Type(), i64val, is_neg);
	assert(llvm_val != NULL);
	llvm_is_neg = LLVMConstInt(LLVMInt1Type(), is_neg, false);
	assert(llvm_is_neg != NULL);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args[1] = llvm_val;
	llvm_fn_args[2] = llvm_is_neg;
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
			      llvm_fn_args_cnt, "") != NULL);
	return true;
}

static void
llvm_build_bool(struct llvm_build_ctx *ctx)
{
	assert(ctx != NULL);


	LLVMValueRef llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg != NULL);
	Expr *expr = ctx->expr;
	assert(expr != NULL);
	LLVMValueRef llvm_val =
		LLVMConstInt(LLVMInt1Type(), expr->op == TK_TRUE, false);
	assert(llvm_val != NULL);
	LLVMModuleRef m = ctx->module;
	assert(m != NULL);
	LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_mem_set_bool);
	assert(llvm_fn != NULL);
	LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type != NULL);
	LLVMValueRef llvm_fn_args[] = { llvm_tgt_reg, llvm_val };
	unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
	LLVMBuilderRef b = ctx->builder;
	assert(b != NULL);

	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
			      llvm_fn_args_cnt, "") != NULL);
}

static bool
llvm_build_double(struct llvm_build_ctx *ctx, bool is_neg)
{
	assert(ctx != NULL);

	Expr *expr = ctx->expr;
	assert(expr != NULL);
	char *z = expr->u.zToken;
	assert(z != NULL);
	assert(!ExprHasProperty(expr, EP_IntValue));
	/* FIXME: is this conversion legit? */
	int len = sqlStrlen30(z);
	assert(len > 0);
	double val;
	LLVMValueRef llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg != NULL);
	LLVMValueRef llvm_val;
	LLVMModuleRef m = ctx->module;
	assert(m != NULL);
	LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_mem_set_double);
	assert(llvm_fn != NULL);
	LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type != NULL);
	LLVMValueRef llvm_fn_args[2];
	unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
	LLVMBuilderRef b = ctx->builder;
	assert(b != NULL);

	if (sqlAtoF(z, &val, len) == 0) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "failed to convert string to double");
		return false;
	}
	assert(sqlIsNaN(val) == 0);
	if (is_neg)
		val = -val;
	llvm_val = LLVMConstReal(LLVMDoubleType(), val);
	assert(llvm_val != NULL);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args[1] = llvm_val ;
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
			      llvm_fn_args_cnt, "") != NULL);
	return true;
}

static bool
llvm_build_str(struct llvm_build_ctx *build_ctx)
{
	assert(build_ctx != NULL);

	Expr *expr = build_ctx->expr;
	assert(expr != NULL);
	char *z = expr->u.zToken;
	assert(z != NULL);
	assert(!ExprHasProperty(expr, EP_IntValue));
	/* FIXME: is this conversion legit? */
	int len = sqlStrlen30(z);
	Parse *parse_ctx = build_ctx->parse_ctx;
	assert(parse_ctx != NULL);
	sql *db = parse_ctx->db;
	assert(db != NULL);
	LLVMValueRef llvm_tgt_reg = build_ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg != NULL);
	LLVMBuilderRef b = build_ctx->builder;
	assert(b != NULL);
	LLVMValueRef llvm_z = LLVMBuildGlobalStringPtr(b, z, "");
	assert(llvm_z != NULL);
	LLVMModuleRef m = build_ctx->module;
	assert(m != NULL);
	LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_mem_set_str0_static);
	assert(llvm_fn != NULL);
	LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type != NULL);
	LLVMValueRef llvm_fn_args[] = { llvm_tgt_reg, llvm_z };
	unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);

	/* FIXME: what is the best way to handle this? */
	if (len > db->aLimit[SQL_LIMIT_LENGTH]) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "string or blob too big");
		return false;
	}
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
			      llvm_fn_args_cnt, "") != NULL);
	return true;
}

static void
llvm_build_null(struct llvm_build_ctx *ctx)
{
	assert(ctx != NULL);

	LLVMValueRef llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg != NULL);
	LLVMModuleRef m = ctx->module;
	assert(m != NULL);
	LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_mem_set_null);
	assert(llvm_fn != NULL);
	LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type != NULL);
	LLVMValueRef llvm_fn_args[] = { llvm_tgt_reg };
	unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
	LLVMBuilderRef b = ctx->builder;
	assert(b != NULL);

	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
			      llvm_fn_args_cnt, "") != NULL);
}

static bool
llvm_build_vdbe_op_column(struct llvm_build_ctx *ctx, int tab, int col)
{
	assert(ctx != NULL);
	assert(tab >= 0);
	assert(col >= 0);

	int tgt_reg_idx = ctx->tgt_reg_idx;
	assert(tgt_reg_idx > 0);
	struct llvm_col_ref_meta curr_col_ref_meta = {
		.tab = tab,
		.col = col,
		.tgt_reg_idx = tgt_reg_idx
	};
	LLVMValueRef llvm_cb = curr_col_ref_meta.llvm_cb = ctx->llvm_cb;
	assert(llvm_cb != NULL);
	LLVMValueRef llvm_regs = curr_col_ref_meta.llvm_regs = ctx->llvm_regs;
	assert(llvm_regs != NULL);
	LLVMBuilderRef b = ctx->builder;
	assert(b != NULL);
	LLVMModuleRef m = ctx->module;
	assert(m != NULL);
	LLVMContextRef m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx != NULL);
	LLVMBasicBlockRef op_column_bb_begin = curr_col_ref_meta.bb_begin =
		LLVMCreateBasicBlockInContext(m_ctx, "OP_Column_begin");
	assert(op_column_bb_begin != NULL);
	LLVMValueRef llvm_vdbe = ctx->llvm_vdbe;
	assert(llvm_vdbe != NULL);
	LLVMValueRef llvm_tab_var;
	LLVMValueRef llvm_tab_imm = LLVMConstInt(LLVMInt32Type(), tab, false);
	assert(llvm_tab_imm != NULL);
	LLVMValueRef llvm_tab_store;
	LLVMValueRef llvm_col_var;
	LLVMValueRef llvm_col_imm = LLVMConstInt(LLVMInt32Type(), col, false);
	assert(llvm_col_imm != NULL);
	LLVMValueRef llvm_col_store;
	LLVMValueRef llvm_tgt_reg_idx = ctx->llvm_tgt_reg_idx;
	assert(llvm_tgt_reg_idx != NULL);
	LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_vdbe_op_column);
	assert(llvm_fn != NULL);
	LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type != NULL);
	LLVMValueRef llvm_fn_args[4];
	unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
	LLVMValueRef llvm_rc;
	LLVMBasicBlockRef op_col_end_bb = curr_col_ref_meta.bb_end =
		LLVMCreateBasicBlockInContext(m_ctx, "OP_Column_end");
	Expr *expr = ctx->expr;
	assert(expr != NULL);
	int col_ref_meta_cnt = ctx->col_ref_meta_cnt;
	assert(col_ref_meta_cnt >= 0);
	struct llvm_col_ref_meta *col_ref_meta = ctx->col_ref_meta;
	size_t col_ref_meta_sz;
	Parse *parse_ctx = ctx->parse_ctx;
	assert(parse_ctx != NULL);
	struct region *region = &parse_ctx->region;

	LLVMInsertExistingBasicBlockAfterInsertBlock(b, op_column_bb_begin);
	LLVMBuildBr(b, op_column_bb_begin);
	LLVMPositionBuilderAtEnd(b, op_column_bb_begin);
	llvm_tab_var = curr_col_ref_meta.llvm_tab_var =
		LLVMBuildAlloca(b, LLVMInt32Type(), "tab");
	assert(llvm_tab_var != NULL);
	llvm_tab_store = curr_col_ref_meta.llvm_tab_store =
		LLVMBuildStore(b, llvm_tab_imm, llvm_tab_var);
	assert(llvm_tab_store != NULL);
	llvm_tab_var = LLVMBuildLoad2(b, LLVMInt32Type(), llvm_tab_var, "");
	assert(llvm_tab_var != NULL);
	llvm_col_var = curr_col_ref_meta.llvm_col_var =
		LLVMBuildAlloca(b, LLVMInt32Type(), "col");
	assert(llvm_col_var != NULL);
	llvm_col_store = curr_col_ref_meta.llvm_col_store =
		LLVMBuildStore(b, llvm_col_imm, llvm_col_var);
	assert(llvm_col_store != NULL);
	llvm_col_var = LLVMBuildLoad2(b, LLVMInt32Type(), llvm_col_var, "");
	assert(llvm_col_var != NULL);
	llvm_fn_args[0] =  llvm_vdbe;
	llvm_fn_args[1] = llvm_tab_var;
	llvm_fn_args[2] = llvm_col_var;
	llvm_fn_args[3] = llvm_tgt_reg_idx;
	llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				 llvm_fn_args_cnt, "rc");
	assert(llvm_rc != NULL);
	llvm_build_rc_check(ctx, llvm_rc);
	assert(op_col_end_bb != NULL);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, op_col_end_bb);
	ALWAYS(LLVMBuildBr(b, op_col_end_bb) != NULL);
	LLVMPositionBuilderAtEnd(b, op_col_end_bb);
	if (!expr->op2)
		sqlExprCacheStore(parse_ctx, tab, col, tgt_reg_idx);
	if (col_ref_meta_cnt == 0) {
		assert(col_ref_meta == NULL);
		region = &parse_ctx->region;
		col_ref_meta =
			region_alloc_array(region,
					   typeof(struct llvm_col_ref_meta),
					   1,
					   &col_ref_meta_sz);
		if (col_ref_meta == NULL)
			goto region_alloc_err;
	} else if (IsPowerOfTwo(col_ref_meta_cnt)) {
		assert(col_ref_meta != NULL);
		region = &parse_ctx->region;
		col_ref_meta =
			region_alloc_array(region,
					   typeof(struct llvm_col_ref_meta),
					   col_ref_meta_cnt << 1,
					   &col_ref_meta_sz);
		if (col_ref_meta == NULL)
			goto region_alloc_err;
		memcpy(col_ref_meta, ctx->col_ref_meta,
		       col_ref_meta_cnt * sizeof(struct llvm_col_ref_meta));
		/*
		 * FIXME: is it okay that we do not clean up previously
		 * allocated memory?
		 */
	}
	if (col_ref_meta != ctx->col_ref_meta) {
		assert(col_ref_meta != NULL);
		ctx->col_ref_meta = col_ref_meta;
	}
	col_ref_meta[ctx->col_ref_meta_cnt++] = curr_col_ref_meta;
	return true;

region_alloc_err:
	diag_set(OutOfMemory, col_ref_meta_sz, "region_alloc_array",
		 "struct llvm_col_ref_meta");
	parse_ctx->is_aborted = true;
	return false;
}

static void
llvm_build_mem_copy(struct llvm_build_ctx *ctx, int src_reg_idx,
		    int dst_reg_idx)
{
	assert(ctx != NULL);
	assert(src_reg_idx >= 0);
	assert(dst_reg_idx >= 0);

	LLVMValueRef llvm_regs = ctx->llvm_regs;
	assert(llvm_regs != NULL);
	LLVMValueRef llvm_src_reg_idx =
		LLVMConstInt(LLVMInt32Type(), src_reg_idx, false);
	assert(llvm_src_reg_idx != NULL);
	LLVMBuilderRef b = ctx->builder;
	assert(b != NULL);
	LLVMValueRef llvm_src_reg =
		LLVMBuildInBoundsGEP2(b, llvm_mem_type, llvm_regs,
				      &llvm_src_reg_idx, 1, "src_reg");
	assert(llvm_src_reg != NULL);
	LLVMValueRef llvm_dst_reg_idx =
		LLVMConstInt(LLVMInt32Type(), dst_reg_idx, false);
	assert(llvm_dst_reg_idx != NULL);
	LLVMValueRef llvm_dst_reg =
		LLVMBuildInBoundsGEP2(b, llvm_mem_type, llvm_regs,
				      &llvm_dst_reg_idx, 1, "dst_reg");
	assert(llvm_dst_reg != NULL);
	LLVMModuleRef m = ctx->module;
	assert(m != NULL);
	/* FIXME: copy operation can depend on SQL_ECEL_DUP */
	LLVMValueRef llvm_fn = llvm_get_fn(m, llvm_mem_copy);
	assert(llvm_fn != NULL);
	LLVMTypeRef llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type != NULL);
	LLVMValueRef llvm_fn_args[] = { llvm_dst_reg, llvm_src_reg };
	unsigned int llvm_fn_args_cnt = lengthof(llvm_fn_args);
	LLVMValueRef llvm_rc =
		LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
			       llvm_fn_args_cnt, "rc");
	assert(llvm_rc != NULL);

	llvm_build_rc_check(ctx, llvm_rc);
}

static void
llvm_build_rc_check(struct llvm_build_ctx *ctx, LLVMValueRef llvm_rc)
{
	assert(ctx != NULL);
	assert(llvm_rc != NULL);

	LLVMModuleRef m = ctx->module;
	assert(m != NULL);
	LLVMContextRef m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx != NULL);
	LLVMBuilderRef b = ctx->builder;
	assert(b != NULL);
	LLVMBasicBlockRef curr_bb = LLVMGetInsertBlock(b);
	assert(curr_bb != NULL);
	LLVMBasicBlockRef err_bb = LLVMCreateBasicBlockInContext(m_ctx, "err");
	assert(err_bb != NULL);
	LLVMValueRef llvm_false = LLVMConstInt(LLVMInt1Type(), false, false);
	assert(llvm_false != NULL);
	LLVMBasicBlockRef ok_bb = LLVMCreateBasicBlockInContext(m_ctx, "ok");
	assert(ok_bb != NULL);
	LLVMValueRef llvm_ok = LLVMConstInt(LLVMInt32Type(), 0, false);
	assert(llvm_ok != NULL);
	LLVMValueRef llvm_if;

	LLVMInsertExistingBasicBlockAfterInsertBlock(b, err_bb);
	LLVMPositionBuilderAtEnd(b, err_bb);
	ALWAYS(LLVMBuildRet(b, llvm_false) != NULL);
	LLVMInsertExistingBasicBlockAfterInsertBlock(b, ok_bb);
	LLVMPositionBuilderAtEnd(b, curr_bb);
	llvm_if = LLVMBuildICmp(b, LLVMIntNE, llvm_rc, llvm_ok, "cond");
	assert(llvm_if != NULL);
	ALWAYS(LLVMBuildCondBr(b, llvm_if, err_bb, ok_bb) != NULL);
	LLVMPositionBuilderAtEnd(b, ok_bb);
}