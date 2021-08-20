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

#pragma once

#include "sqlInt.h"
#include "whereInt.h"

#include "box/session.h"

#include "llvm-c/Core.h"
#include "llvm-c/Orc.h"

/**
 * Minimal expression list item height to consider LLVM JIT compilation of
 * expression list.
 */
enum {
	LLVM_JIT_MIN_TOTAL_EXPR_LIST_HEIGHT = 1
};

/** Metadata for patching OP_Column code. */
struct llvm_col_ref_meta {
	/** Callback function, containing OP_Column code. */
	LLVMValueRef llvm_cb;
	/** VDBE registers array. */
	LLVMValueRef llvm_regs;
	/** Basic block where OP_Column code starts. */
	LLVMBasicBlockRef bb_begin;
	/** Basic block at which OP_Column code ends. */
	LLVMBasicBlockRef bb_end;
	/** Cursor number local variable. */
	LLVMValueRef llvm_tab_var;
	/** Store instruction into the cursor number local variable. */
	LLVMValueRef llvm_tab_store;
	/** Cursor number. */
	int tab;
	/** Column number local variable. */
	LLVMValueRef llvm_col_var;
	/** Store instruction into the column number local variable. */
	LLVMValueRef llvm_col_store;
	/** Column number */
	int col;
	/** Target register's index. */
	int tgt_reg_idx;
};

/**
 * LLVM construction context used to hold useful information during construction
 * of expression lists.
 */
struct llvm_build_ctx {
	/** Module in which callback functions are built. */
	LLVMModuleRef module;
	/** Generation of LLVM IR into basic blocks. */
	LLVMBuilderRef builder;
	/** Current parsing context. */
	Parse *parse_ctx;
	/** False if at least one callback function was built. */
	bool module_empty;
	/** ID of current callback function under construction. */
	int cb_id;
	/** Current callback function under construction. */
	LLVMValueRef llvm_cb;
	/** VDBE pointer passed to the callback function. */
	LLVMValueRef llvm_vdbe;
	/** VDBE registers array. */
	LLVMValueRef llvm_regs;
	/** Source registers index, for use by SQL_ECEL_OMIT_REF optimization. */
	int src_regs_idx;
	/** Target registers index, to which expression values are pushed. */
	int tgt_regs_idx;
	/** Current expression processed. */
	Expr *expr;
	/** VDBE target register index for current expression (numerical value). */
	int tgt_reg_idx;
	/** VDBE target register index for current expression (LLVM value). */
	LLVMValueRef llvm_tgt_reg_idx;
	/** VDBE target register for current expression. */
	LLVMValueRef llvm_tgt_reg;
	/**
	 * Array for each column reference module_passed_to_lljit. Ownership after build
	 * stage is transferred to the corresponding VdbeOp. May be used to patch
	 * column references' table and column number or even change the OP_Column
	 * block of code to an OP_Copy in @sqlWhereEnd. Allocated as a
	 * power of 2 in parsing context's region.
	 */
	struct llvm_col_ref_meta *col_ref_meta;
	/** Size of col_ref_meta array. */
	int col_ref_meta_cnt;
	/**
	 * Array for each aggregate function module_passed_to_lljit. Each element references
	 * a pointer to an sql_context in LLVM IR. Allocated once in parsing
	 * context's region.
	 */
	LLVMValueRef *llvm_agg_sql_ctx;
	/** Basic block where the aggregate query loop starts. */
	LLVMBasicBlockRef agg_loop_bb;
};

/**
 * LLVM JIT context, holds all necessary data for the JIT infrastructure.
 */
struct llvm_jit_ctx {
	/** Module in which callback functions are built. */
	LLVMModuleRef module;
	/** Resource tracker of main LLVM JITDyLib. */
	LLVMOrcResourceTrackerRef rt;
	/**
	 * Build context: allocated once in parsing context's region
	 * when llvm_jit_ctx_new is called.
	 */
	struct llvm_build_ctx *build_ctx;
	/**
	 * Number of functions currently built — used to generate
	 * non-conflicting callback function names.
	 */
	int cb_cnt;
};

/** Initialize the LLVM subsystem and the LLVM JIT infrastructure.  */
bool
llvm_session_init(void);

/** Check whether the LLVM JIT infrastructure is available. */
static inline bool
llvm_jit_available(void)
{
	if (!sql_get()->llvm_session_ini)
		return false;
	if ((current_session()->sql_flags & SQL_VdbeLLVMJIT) == 0)
		return false;
	return true;
}

/** Allocate a new LLVM JIT context from the parsing context's region. */
struct llvm_jit_ctx *
llvm_jit_ctx_new(Parse *parse_ctx);

/** Delete the LLVM JIT context. */
void
llvm_jit_ctx_delete(struct llvm_jit_ctx *jit_ctx);

/**
 * Build loop consisting of pushing aggregate function arguments,
 * executing aggregate functions step and updating columns stored in
 * AggInfo->aCol.
 */
bool
llvm_build_agg_loop(struct llvm_jit_ctx *jit_ctx, WhereInfo *where_info,
		    AggInfo *agg_info);
/**
 * Build expression list, consisting of pushing a set of expresions to target
 * VDBE registers.
 */
bool
llvm_build_expr_list(struct llvm_jit_ctx *jit_ctx, Parse *parse_ctx,
		     ExprList *expr_list, int *expr_cnt, int src_regs_idx,
		     int tgt_regs_idx, u8 flags);

/**
 * Execute the module_passed_to_lljit expression list via the callback function:
 * push expression values to target registers.
 */
bool
llvm_exec_compiled_cb(struct llvm_jit_ctx *ctx, int cb_id, Vdbe *vdbe);

/**
 * Verify the LLVM module containing built callback functions and clean up
 * resources used by the build context.
 */
bool
llvm_jit_ctx_fin(struct llvm_jit_ctx *jit_ctx);

/**
 * Remove basic blocks containing OP_Column code and insert OP_Copy code
 * instead of it.
 */
void
llvm_jit_change_col_refs_to_reg_copies(struct llvm_jit_ctx *jit_ctx,
				       struct llvm_col_ref_meta *col_ref_meta,
				       int col_ref_meta_cnt, int tab,
				       int coro_src_regs_idx);

/**
 * Patch cursor and column numbers for columns referring to indices.
 */
void
llvm_jit_patch_idx_col_refs(struct llvm_jit_ctx *jit_ctx, WhereLevel *where_lvl,
			    struct index_def *idx_def,
			    struct llvm_col_ref_meta *col_ref_meta,
			    int col_ref_meta_cnt);