#pragma once

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

#include "sqlInt.h"

#include "box/session.h"

/** Minimal expression list item height to consider using JIT compilation. */
enum {
	JIT_MIN_TOTAL_EXPR_LIST_HEIGHT = 1
};

/** Minimal tuple count to consider using JIT compilation. */
enum {
	JIT_MIN_TUPLE_CNT = 1
};

bool
llvm_session_init(void);

static inline bool
llvm_jit_enabled(void)
{
	if (!sql_get()->llvm_session_init)
		return false;
	if ((current_session()->sql_flags & SQL_VdbeJIT) == 0)
		return false;
	return true;
}

void
llvm_build_expr_list_init(Parse *parse, int src_regs, int tgt_regs);

bool
llvm_build_expr_list_fin(struct llvm_jit_ctx *jit_ctx);

bool
llvm_build_expr_list_item(struct llvm_jit_ctx *jit_ctx,
			  struct ExprList_item *item, int expr_idx,
			  int flags);

bool
llvm_exec_compiled_expr_list(struct llvm_jit_ctx *ctx, int fn_id, Vdbe *vdbe);

void
llvm_jit_ctx_delete(struct llvm_jit_ctx *ctx);

int
llvm_jit_get_fn_under_construction_id(struct llvm_jit_ctx *ctx);

bool
llvm_jit_verify(struct llvm_jit_ctx *jit_ctx);