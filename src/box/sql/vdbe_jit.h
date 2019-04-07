#ifndef TARANTOOL_SQL_VDBE_JIT_H_INCLUDED
#define TARANTOOL_SQL_VDBE_JIT_H_INCLUDED
/*
 * Copyright 2010-2019, Tarantool AUTHORS, please see AUTHORS file.
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

#include <stdint.h>
#include "sqlInt.h"
#include "vdbeInt.h"

#include "box/session.h"

#include "llvm-c/Core.h"
#include "llvm-c/ExecutionEngine.h"
#include "llvm-c/OrcBindings.h"

enum binop { ADD = 0, SUB, DIV, MUL };

enum cmpop { LE = 0, LT, GE, GT, EQ, NE };

enum predicate { AND = 0, OR };

enum jit_compilation_strategy {
	/**
	 * Compile and execute expr. Result is saved to output
	 * VDBE memory cell. Compiled bitcode is invoked inside
	 * outer VDBE cycle-loop.
	 */
	COMPILE_EXPR_RS = 0,
	/**
	 * Compile and execute expr. Result is dumped to port.
	 * Compiled bitcode contains jitted loop, so there's no
	 * need to return control back to VDBE.
	 */
	COMPILE_EXPR_WITH_DUMP,
	COMPILE_EXPR_WHERE_COND,
	COMPILE_EXPR_AGG,
	COMPILE_EXPR_AGG_STEP
};

enum jit_implementation {
	LLVM_JIT_ORC = 0,
	LLVM_JIT_MC = 1,
};

/** Minimal total height of expression list to consider using JIT. */
enum {
	JIT_MIN_TOTAL_EXPR_HEIGHT = 1
};

/** Minimal count of tuples to consider using JIT. */
enum {
	JIT_MIN_TUPLE_COUNT = 1
};

/**
 * We can compile expressions in different parts of query:
 * expression can be part of result set, where predicate
 * or nested query.
 */
struct jit_func_context {
	/** Function under construction. */
	LLVMValueRef func;
	char *name;
	/** Place to save results of function execution. */
	LLVMValueRef *output_args;
	LLVMValueRef tuple;
	LLVMValueRef result;
	/** Function pattern. */
	enum jit_compilation_strategy strategy;
};

/**
 * This structure aggregates all required information during
 * compilation to LLVM IR. Only module will survive till
 * execution, all other members will be thrown or released.
 */
struct jit_compile_context {
	/**
	 * Will be passed to execute context and released at
	 * the end of VDBE execution. It holds all required
	 * information: variables, functions etc.
	 */
	LLVMModuleRef module;
	/**
	 * Builder is used to create basic blocks and LLVM
	 * IR instructions.
	 */
	LLVMBuilderRef builder;
	/**
	 * Represent current LLVM IR function being constructed.
	 */
	struct jit_func_context *func_ctx;
	/**
	 * We can't allow names collisions, so we mangle them
	 * with ordinal number.
	 */
	uint32_t func_count;
	/**
	 * To avoid decoding the same field several times, we use
	 * hash to keep already decoded fields.
	 */
	struct mh_i32ptr_t *decoded_fields;
};

struct jit_execute_context {
	/** Module obtained from compile context. */
	LLVMModuleRef module;
	/** Depending on used engine, we utilize one of these members. */
	union {
		LLVMExecutionEngineRef engine;
		LLVMOrcModuleHandle module_handle;
	};
	enum jit_implementation jit_impl;
	bool is_compiled;
};

static inline bool
jit_is_enabled()
{
	if (! sql_get()->vdbe_jit_init)
		return false;
	if ((current_session()->sql_flags & SQL_VdbeJIT) == 0)
		return false;
	return true;
}

/** ==============================================================
 *
 * Functions which are called to compile LLVM IR for JIT.
 */

void
jit_compile_context_release(struct jit_compile_context *context);

int
jit_expr_emit_start(struct jit_compile_context *context, uint32_t expr_count);

int
jit_expr_emit_finish(struct jit_compile_context *context);

int
jit_emit_expr(struct jit_compile_context *context, struct Expr *expr,
	      uint32_t expr_no);

int
jit_emit_agg(struct jit_compile_context *context, const char *agg_name);

/** ==============================================================
 *
 * Functions which are called directly in jitted code to implement
 * basic actions like addition or field decode from tuple.
 */

int
jit_tuple_field_fetch(struct tuple *tuple, uint32_t fieldno, struct Mem *output);

int
jit_mem_binop_exec(struct Mem *lhs, struct Mem *rhs, int op, struct Mem *output);

int
jit_mem_cmp_exec(struct Mem *lhs, struct Mem *rhs, int cmp, struct Mem *output);

int
jit_mem_predicate_exec(struct Mem *lhs, struct Mem *rhs, int predicate,
		       struct Mem *output);

int
jit_mem_concat_exec(struct Mem *lhs, struct Mem *rhs, int unused,
		    struct Mem *output);

int
jit_agg_max_exec(struct Mem *best, struct Mem *current);

int
jit_agg_count_exec(struct Mem *count, struct Mem *current);

int
jit_agg_sum_exec(struct Mem *sum, struct Mem *current);

void
jit_debug_print(const char *msg);

int
jit_mem_to_port(struct Mem *mem, int mem_count, struct port *port);

/** ==============================================================
 *
 * Functions which are called during execution of VDBE.
 */

void
jit_execute_context_release(struct jit_execute_context *context);

int
jit_mc_engine_prepare(struct jit_execute_context *context,
		      LLVMExecutionEngineRef *engine);

int
jit_mc_engine_finalize(struct jit_execute_context *context,
		       LLVMExecutionEngineRef engine);

int
jit_execute(struct jit_execute_context *context, struct tuple *tuple,
	    char *func_name, struct Mem *result);

int
jit_execute_with_dump(struct jit_execute_context *context, struct tuple *tuple,
		      struct port *port);

#endif /* TARANTOOL_SQL_VDBE_JIT_H_INCLUDED */
