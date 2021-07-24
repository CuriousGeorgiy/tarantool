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
#include "llvm_jit_lib.h"

#include "mem.h"
#include "sqlInt.h"
#include "vdbeInt.h"
#include "vdbe.h"

#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/LLJIT.h"
#include "llvm-c/OrcEE.h"
#include "llvm-c/Support.h"
#include "llvm-c/Target.h"

/** Used for callback function name generation. */
static const char *const fn_name_prefix = "expr_";

/** Types referenced during construction of LLVM IR. */
static LLVMTypeRef llvm_vdbe_type;
static LLVMTypeRef llvm_vdbe_ptr_type;
static LLVMTypeRef llvm_vdbe_field_ref_type;
static LLVMTypeRef llvm_mem_type;
static LLVMTypeRef llvm_mem_ptr_type;

/** Auxiliary functions referenced during construction of LLVM IR. */
static LLVMValueRef llvm_mem_copy;
static LLVMValueRef llvm_mem_set_null;
static LLVMValueRef llvm_mem_set_int;
static LLVMValueRef llvm_mem_set_bool;
static LLVMValueRef llvm_mem_set_double;
static LLVMValueRef llvm_mem_set_str0_static;
static LLVMValueRef llvm_vdbe_field_ref_fetch;
static LLVMValueRef llvm_vdbe_op_col;

/** LLVM Orc LLJIT instance. */
static LLVMOrcLLJITRef llvm_lljit;
/* FIXME: should be disposed sometime? */

/**
 * Module containing type definitions and auxiliary functions implementation.
 * Other modules are cloned from it in order to contain the implementation of
 * all auxiliary functions so that they can be inlined.
 */
static LLVMModuleRef llvm_base_mod;

/**
 * Create the base module from an embedded LLVM bitcode string, populate the
 * base types.
 */
static bool
llvm_base_module_create(void);

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

/** Allocate a new llvm_jit_ctx from parsing context's region. */
static struct llvm_jit_ctx *
llvm_jit_ctx_new(Parse *parse_ctx);

/**
 * Retrieve the error message string from LLVMErrorRef and disposes it,
 * preliminarily saving the error message to the static buffer.
 */
static const char *
llvm_get_err_msg(LLVMErrorRef err);

/** Callback function passed to LLVMOrcExecutionSessionSetErrorReporter. */
static void
llvm_log_jit_error(void *unused, LLVMErrorRef err);

/** Build a return code check. */
static void
llvm_build_rc_check(struct llvm_build_ctx *ctx, LLVMValueRef llvm_rc);

/** Build a null value. */
static void
llvm_build_null(struct llvm_build_ctx *ctx);

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

/** Build a column reference value. */
static void
build_col_ref(struct llvm_build_ctx *build_ctx);

/** Build the current expression. */
static bool
llvm_build_expr(struct llvm_build_ctx *ctx);

/** Compile the current module. */
static bool
llvm_compile_module(struct llvm_jit_ctx *ctx);

bool
llvm_session_init(void)
{
	assert(sql_get());
	assert(!sql_get()->llvm_session_init);

	LLVMContextRef global_ctx;
	const char *llvm_triple;
	LLVMTargetRef llvm_t;
	LLVMTargetMachineRef default_tm;
	char *err_msg;
	char *cpu_name;
	char *cpu_feats;

	global_ctx = LLVMGetGlobalContext();
	assert(global_ctx);
	LLVMContextSetDiagnosticHandler(global_ctx, llvm_diag_handler, NULL);
	if (LLVMInitializeNativeTarget() != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to initialize native target");
		return false;
	}
	if (LLVMInitializeNativeAsmPrinter() != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to initialize native asm printer");
		return false;
	}
	if (LLVMInitializeNativeAsmParser() != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to initialize native asm parser");
		return false;
	}
	if (!llvm_base_module_create())
		return false;
	llvm_triple = LLVMGetTarget(llvm_base_mod);
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
	/* force symbols in tarantool binary to be loaded */
	if (LLVMLoadLibraryPermanently(NULL) != 0) {
		/* FIXME: move to diag_set */
		say_error("failed to load symbols from tarantool binary");
		return false;
	}
	if (!llvm_lljit_inst_create(default_tm))
		return false;
	sql_get()->llvm_session_init = true;
	return true;
}

struct llvm_jit_ctx *
parse_get_jit_ctx(Parse *parse_ctx)
{
	assert(parse_ctx);

	struct llvm_jit_ctx *jit_ctx;
	struct region *region;

	jit_ctx = parse_ctx->llvm_jit_ctx;
	region = &parse_ctx->region;
	if (!jit_ctx) {
		jit_ctx = llvm_jit_ctx_new(parse_ctx);
		if (!jit_ctx) {
			parse_ctx->is_aborted = true;
			return NULL;
		}
		parse_ctx->llvm_jit_ctx = jit_ctx;
	}
	return jit_ctx;
}

void
llvm_build_expr_list_init(Parse *parse, int src_regs, int tgt_regs)
{
	assert(parse);
	assert(src_regs >= 0);
	assert(tgt_regs > 0);

	struct llvm_jit_ctx *jit_ctx;
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

	jit_ctx = parse->llvm_jit_ctx;
	assert(jit_ctx);
	m = jit_ctx->module;
	assert(m);
	td = LLVMGetModuleDataLayout(m);
	assert(td);
	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	fn_id = build_ctx->fn_id = jit_ctx->cnt++;
	b = build_ctx->builder = LLVMCreateBuilder();
	build_ctx->parse_ctx = parse;
	assert(fn_id >= 0);
	build_ctx->src_regs_idx = src_regs;
	build_ctx->tgt_regs_idx = tgt_regs;
	assert(llvm_vdbe_ptr_type);
	fn_param_types[0] = llvm_vdbe_ptr_type;
	llvm_fn_type = LLVMFunctionType(LLVMInt1Type(), fn_param_types,
				   lengthof(fn_param_types), false);
	/*
	 * FIXME: is it actually safe to pass the function name in such a
	 * manner?
	 */
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

bool
llvm_build_expr_list_item(struct llvm_jit_ctx *jit_ctx,
			  struct ExprList_item *item, int expr_idx, int flags)
{
	assert(jit_ctx);
	assert(item);
	assert(expr_idx >= 0);

	struct llvm_build_ctx *build_ctx;
	LLVMBuilderRef b;
	int tgt_reg_idx;
	const char *name;
	int j;
	LLVMValueRef llvm_tgt_reg_idx;
	LLVMValueRef llvm_tgt_reg;

	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	build_ctx->expr = item->pExpr;
	assert(build_ctx->expr);
	b = build_ctx->builder;
	assert(b);
	assert(build_ctx->tgt_regs_idx > 0);
	tgt_reg_idx = build_ctx->tgt_reg_idx = build_ctx->tgt_regs_idx + expr_idx;
	llvm_tgt_reg_idx = build_ctx->llvm_tgt_reg_idx =
		LLVMConstInt(LLVMInt32Type(), tgt_reg_idx , false);
	assert(llvm_tgt_reg_idx);
	name = tt_sprintf("tgt_reg_%d", expr_idx);
	assert(name);
	llvm_tgt_reg = build_ctx->llvm_tgt_reg =
		LLVMBuildInBoundsGEP2(b, llvm_mem_type, build_ctx->llvm_regs,
				      &llvm_tgt_reg_idx, 1, name);
	assert(llvm_tgt_reg);
	if ((flags & SQL_ECEL_REF) != 0
	    && (j = item->u.x.iOrderByCol) > 0) {
		assert((flags & SQL_ECEL_OMITREF) == 0);
		int src_reg_idx;
		LLVMValueRef llvm_src_reg_idx;
		LLVMValueRef llvm_src_reg;
		LLVMValueRef llvm_fn;
		LLVMTypeRef llvm_fn_type;
		LLVMValueRef llvm_fn_args[2];
		unsigned int llvm_fn_args_cnt;
		LLVMValueRef llvm_rc;

		assert(build_ctx->src_regs_idx > 0);
		src_reg_idx = build_ctx->src_regs_idx + j - 1;
		llvm_src_reg_idx =
			LLVMConstInt(LLVMInt32Type(), src_reg_idx, false);
		assert(llvm_src_reg_idx);
		name = tt_sprintf("src_reg_%d", j);
		assert(name);
		llvm_src_reg =
			LLVMBuildInBoundsGEP2(b, llvm_mem_type,
					      build_ctx->llvm_regs,
					      &llvm_src_reg_idx, 1, name);
		assert(llvm_src_reg);
		/* FIXME: copy operation depending on SQL_ECEL_DUP */
		llvm_fn = llvm_mem_copy;
		assert(llvm_fn);
		llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
		assert(llvm_fn_type);
		llvm_fn_args[0] = llvm_tgt_reg;
		llvm_fn_args[1] = llvm_src_reg;
		llvm_fn_args_cnt = lengthof(llvm_fn_args);
		llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
					 llvm_fn_args_cnt, "llvm_rc");
		assert(llvm_rc);
		llvm_build_rc_check(build_ctx, llvm_rc);
		return true;
	}
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
	LLVMValueRef llvm_ok;

	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	b = build_ctx->builder;
	assert(b);
	m = jit_ctx->module;
	assert(m);
	llvm_fn = jit_ctx->build_ctx->llvm_fn;
	assert(llvm_fn);
	llvm_ok = LLVMConstInt(LLVMInt1Type(), true, false);
	assert(llvm_ok);
	ALWAYS(LLVMBuildRet(b, llvm_ok));
	if (LLVMVerifyFunction(llvm_fn, LLVMPrintMessageAction) != 0) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "function IR verification failed");
		return false;
	}
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

	if (!ctx->compiled && !llvm_compile_module(ctx))
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

void
llvm_jit_ctx_delete(struct llvm_jit_ctx *ctx)
{
	LLVMOrcResourceTrackerRef rt;
	LLVMOrcExecutionSessionRef es;
	LLVMOrcSymbolStringPoolRef ssp;
	LLVMErrorRef err;

	if (!ctx)
		return;
	if (ctx->module) {
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
	free(ctx);
}

bool
llvm_jit_verify(struct llvm_jit_ctx *jit_ctx)
{
	assert(jit_ctx);

	LLVMModuleRef m;
	struct llvm_build_ctx *build_ctx;
	char *err_msg;

	build_ctx = jit_ctx->build_ctx;
	assert(build_ctx);
	m = jit_ctx->module;
	if (LLVMPrintModuleToFile(m, "vdbe.ll", &err_msg) != 0) {
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

static bool
llvm_base_module_create(void)
{
	LLVMMemoryBufferRef buf;
	size_t len;
	LLVMContextRef module_ctx;
	struct load_type {
		const char *name;
		LLVMTypeRef *type;
		bool is_ptr;
	} load_types[] = {
	{ "struct.Vdbe", &llvm_vdbe_type, false },
	{ "struct.Vdbe", &llvm_vdbe_ptr_type, true },
	{ "struct.Mem", &llvm_mem_type, false },
	{ "struct.Mem", &llvm_mem_ptr_type, true },
	{ "struct.vdbe_field_ref", &llvm_vdbe_field_ref_type, false },
	};

	len = lengthof(llvm_jit_lib_bin);
	buf = LLVMCreateMemoryBufferWithMemoryRange((const char *)llvm_jit_lib_bin,
						    len, NULL, false);
	assert(buf);
	if (LLVMParseBitcode2(buf, &llvm_base_mod) != 0) {
		/* FIXME: move to diag_set */
		say_error("parsing of LLVM bitcode failed");
		return false;
	}
	assert(llvm_base_mod);
	LLVMDisposeMemoryBuffer(buf);
	buf = NULL;
	module_ctx = LLVMGetModuleContext(llvm_base_mod);
	assert(module_ctx);
	LLVMContextSetDiagnosticHandler(module_ctx, llvm_diag_handler, NULL);
	for (size_t i = 0; i < lengthof(load_types); ++i) {
		struct load_type load_type;
		LLVMTypeRef type;

		load_type = load_types[i];
		type = LLVMGetTypeByName(llvm_base_mod, load_type.name);
		if (type == NULL) {
			/* FIXME: move to diag_set */
			say_error("failed to find type: %s", load_type.name);
			return false;
		}
		*load_type.type = load_type.is_ptr ? LLVMPointerType(type, 0) : type;
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
	char lljit_global_prefix;
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
	lljit_global_prefix = LLVMOrcLLJITGetGlobalPrefix(llvm_lljit);
	err = LLVMOrcCreateDynamicLibrarySearchGeneratorForProcess(&dg,
								   lljit_global_prefix,
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

static struct llvm_jit_ctx *
llvm_jit_ctx_new(Parse *parse_ctx)
{
	assert(parse_ctx);

	size_t jit_ctx_sz;
	struct llvm_jit_ctx *jit_ctx;
	LLVMModuleRef m;
	LLVMContextRef m_ctx;
	size_t build_ctx_sz;
	struct llvm_build_ctx *build_ctx;
	struct load_fn {
		const char *name;
		LLVMValueRef *llvm_fn;
	} load_fns[] = {
	{ "mem_copy", &llvm_mem_copy },
	{ "mem_set_null", &llvm_mem_set_null },
	{ "mem_set_int", &llvm_mem_set_int },
	{ "mem_set_bool", &llvm_mem_set_bool },
	{ "mem_set_double", &llvm_mem_set_double },
	{ "mem_set_str0_static", &llvm_mem_set_str0_static },
	{ "vdbe_field_ref_fetch", &llvm_vdbe_field_ref_fetch },
	{ "vdbe_op_col", &llvm_vdbe_op_col }
	};

	jit_ctx_sz = sizeof(struct llvm_jit_ctx);
	jit_ctx = malloc(jit_ctx_sz);
	if (!jit_ctx) {
		diag_set(OutOfMemory, jit_ctx_sz, "malloc", "struct llvm_jit_ctx");
		return NULL;
	}
	m = jit_ctx->module = LLVMCloneModule(llvm_base_mod);
	assert(m);
	m_ctx = LLVMGetModuleContext(m);
	assert(m_ctx);
	LLVMContextSetDiagnosticHandler(m_ctx, llvm_diag_handler, NULL);
	for (size_t i = 0; i < lengthof(load_fns); ++i) {
		struct load_fn load_fn;
		LLVMValueRef llvm_fn;

		load_fn = load_fns[i];
		llvm_fn = *load_fn.llvm_fn = LLVMGetNamedFunction(m, load_fn.name);
		if (llvm_fn == NULL) {
			/* FIXME: move to diag_set */
			say_error("failed to load function '%s'", load_fn.name);
			return NULL;
		}
	}
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
	memset(jit_ctx->build_ctx, 0, sizeof(struct llvm_build_ctx));
	jit_ctx->cnt = 0;
	return jit_ctx;
}

static void
llvm_build_rc_check(struct llvm_build_ctx *ctx, LLVMValueRef llvm_rc)
{
	assert(ctx);
	assert(llvm_rc);

	LLVMBuilderRef b;
	LLVMValueRef llvm_fn;
	LLVMBasicBlockRef curr_bb;
	LLVMBasicBlockRef then_bb;
	LLVMBasicBlockRef else_bb;
	LLVMValueRef llvm_if;
	LLVMValueRef llvm_false;
	LLVMValueRef llvm_true;

	b = ctx->builder;
	llvm_fn = ctx->llvm_fn;
	curr_bb = LLVMGetInsertBlock(b);
	assert(curr_bb);
	then_bb = LLVMAppendBasicBlock(llvm_fn, "llvm_false");
	assert(then_bb);
	LLVMPositionBuilderAtEnd(b, then_bb);
	llvm_false = LLVMConstInt(LLVMInt1Type(), false, false);
	assert(llvm_false);
	ALWAYS(LLVMBuildRet(b, llvm_false));
	else_bb = LLVMAppendBasicBlock(llvm_fn, "ok");
	assert(else_bb);
	LLVMPositionBuilderAtEnd(b, curr_bb);
	llvm_true = LLVMConstInt(LLVMInt1Type(), true, false);
	assert(llvm_true);
	llvm_if = LLVMBuildICmp(b, LLVMIntNE, llvm_rc, llvm_true, "cond");
	assert(llvm_if);
	ALWAYS(LLVMBuildCondBr(b, llvm_if, then_bb, else_bb));
	LLVMPositionBuilderAtEnd(b, else_bb);
}

static void
llvm_build_null(struct llvm_build_ctx *ctx)
{
	assert(ctx != NULL);

	LLVMBuilderRef b;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[1];
	unsigned int llvm_fn_args_cnt;

	b = ctx->builder;
	assert(b);
	llvm_fn = llvm_mem_set_null;
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
llvm_build_int(struct llvm_build_ctx *ctx, bool is_neg)
{
	assert(ctx);

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

	b = ctx->builder;
	assert(b);
	llvm_fn = llvm_mem_set_int;
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

	LLVMBuilderRef b;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_val;
	Expr *expr;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[2];
	unsigned int llvm_fn_args_cnt;

	b = ctx->builder;
	assert(b);
	expr = ctx->expr;
	assert(expr);
	llvm_tgt_reg = ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	llvm_val = LLVMConstInt(LLVMInt1Type(), expr->op == TK_TRUE, false);
	assert(llvm_val);
	llvm_fn = llvm_mem_set_bool;
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

	LLVMBuilderRef b;
	int len;
	double val;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_val;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[2];
	unsigned int llvm_fn_args_cnt;

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
	llvm_fn = llvm_mem_set_double;
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	llvm_fn_args[0] = llvm_tgt_reg;
	llvm_fn_args[1] = llvm_val ;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	ALWAYS(LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args, llvm_fn_args_cnt, ""));
	return true;
}

static bool
llvm_build_str(struct llvm_build_ctx *build_ctx, const char *z)
{
	assert(build_ctx);
	assert(z);

	LLVMBuilderRef b;
	int len;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_z;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	LLVMValueRef llvm_fn_args[2];
	unsigned int llvm_fn_args_cnt;

	b = build_ctx->builder;
	assert(b);
	/* FIXME: is this conversion legit? */
	len = sqlStrlen30(z);
	assert(len > 0);
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
	llvm_fn = llvm_mem_set_str0_static;
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
build_col_ref(struct llvm_build_ctx *build_ctx)
{
	assert(build_ctx);

	LLVMBuilderRef b;
	Expr *expr;
	int csr;
	int col;
	Parse *parse_ctx;
	LLVMValueRef llvm_tgt_reg;
	LLVMValueRef llvm_tgt_reg_idx;
	int tgt_reg_idx;
	LLVMValueRef llvm_fn;
	LLVMTypeRef llvm_fn_type;
	unsigned int llvm_fn_args_cnt;
	LLVMValueRef llvm_vdbe;
	LLVMValueRef llvm_csr;
	LLVMValueRef llvm_col;
	LLVMValueRef llvm_rc;
	int i;
	struct yColCache *p;

	b = build_ctx->builder;
	assert(b);
	expr = build_ctx->expr;
	assert(expr);
	csr = expr->iTable;
	col = expr->iColumn;
	assert(col >= 0);
	parse_ctx = build_ctx->parse_ctx;
	assert(parse_ctx);
	llvm_tgt_reg = build_ctx->llvm_tgt_reg;
	assert(llvm_tgt_reg);
	llvm_tgt_reg_idx = build_ctx->llvm_tgt_reg_idx;
	assert(llvm_tgt_reg_idx);
	if (csr < 0) {
		if (parse_ctx->vdbe_field_ref_reg > 0) {
			int field_ref_reg_idx;
			LLVMValueRef llvm_field_ref_reg_idx;
			const char *name;
			LLVMValueRef llvm_field_ref_reg;
			LLVMValueRef llvm_field_ref;
			LLVMValueRef llvm_field_no;
			LLVMValueRef llvm_fn_args[3];

			field_ref_reg_idx = parse_ctx->vdbe_field_ref_reg;
			assert(field_ref_reg_idx >= 0);
			llvm_field_ref_reg_idx = LLVMConstInt(LLVMInt64Type(),
							      field_ref_reg_idx,
							      false);
			assert(llvm_field_ref_reg_idx);
			name = "llvm_field_ref_reg";
			llvm_field_ref_reg =
				LLVMBuildInBoundsGEP2(b, llvm_mem_type,
						      build_ctx->llvm_regs,
						      &llvm_field_ref_reg_idx,
						      1, name);
			assert(llvm_field_ref_reg);
			name = "field_ref";
			llvm_field_ref =
				LLVMBuildBitCast(b, llvm_field_ref_reg,
						 llvm_vdbe_field_ref_type, name);
			assert(llvm_field_ref);
			llvm_fn = llvm_vdbe_field_ref_fetch;
			assert(llvm_fn);
			llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
			assert(llvm_fn_type);
			llvm_field_no =
				LLVMConstInt(LLVMInt32Type(), col, false);
			assert(llvm_field_no);
			llvm_fn_args[0] = llvm_field_ref;
			llvm_fn_args[1] = llvm_field_no;
			llvm_fn_args[2] = llvm_tgt_reg;
			llvm_fn_args_cnt = lengthof(llvm_fn_args);
			llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
						 llvm_fn_args_cnt, "rc");
			assert(llvm_rc);
			llvm_build_rc_check(build_ctx, llvm_rc);
			return;
		} else {
			/*
			 * Coding an expression that is part of an index where
			 * column names in the index refer to the table to which
			 * the index belongs.
			 */
			csr = parse_ctx->iSelfTab;
		}
	}
	for (i = 0, p = parse_ctx->aColCache; i < parse_ctx->nColCache; ++i, ++p) {
		if (p->iTable == csr && p->iColumn == col) {
			p->lru = parse_ctx->iCacheCnt++;
			assert(p->lru >= 0);
			assert(p->iReg > 0);

			LLVMValueRef llvm_idx;
			const char *name;
			LLVMValueRef llvm_cached_column_reg;
			LLVMValueRef llvm_regs;
			LLVMValueRef llvm_fn_args[2];

			sqlExprCachePinRegister(parse_ctx, p->iReg);
			llvm_regs = build_ctx->llvm_regs;
			assert(llvm_regs);
			llvm_idx = LLVMConstInt(LLVMInt64Type(), p->iReg, false);
			assert(llvm_idx);
			name = "cached_col_reg";
			llvm_cached_column_reg =
				LLVMBuildInBoundsGEP2(b, llvm_mem_type,
						      llvm_regs, &llvm_idx, 1,
						      name);
			assert(llvm_cached_column_reg);
			/* FIXME: copy operation depending on SQL_ECEL_DUP */
			llvm_fn = llvm_mem_copy;
			assert(llvm_fn);
			llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
			assert(llvm_fn_type);
			llvm_fn_args[0] = llvm_tgt_reg;
			llvm_fn_args[1] =llvm_cached_column_reg;
			llvm_fn_args_cnt = lengthof(llvm_fn_args);
			llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
					      llvm_fn_args_cnt, "");
			llvm_build_rc_check(build_ctx, llvm_rc);
			return;
		}
	}

	LLVMValueRef llvm_fn_args[5];

	llvm_vdbe = build_ctx->llvm_vdbe;
	assert(llvm_vdbe);
	llvm_csr = LLVMConstInt(LLVMInt32Type(), csr, false);
	assert(llvm_csr);
	llvm_col = LLVMConstInt(LLVMInt32Type(), col, false);
	assert(llvm_col);
	llvm_fn = llvm_vdbe_op_col;
	assert(llvm_fn);
	llvm_fn_type = LLVMGetElementType(LLVMTypeOf(llvm_fn));
	assert(llvm_fn_type);
	llvm_fn_args[0] = llvm_vdbe;
	llvm_fn_args[1] = llvm_csr;
	llvm_fn_args[2] = llvm_col;
	llvm_fn_args[3] = llvm_tgt_reg;
	llvm_fn_args[4] = llvm_tgt_reg_idx;
	llvm_fn_args_cnt = lengthof(llvm_fn_args);
	llvm_rc = LLVMBuildCall2(b, llvm_fn_type, llvm_fn, llvm_fn_args,
				 llvm_fn_args_cnt, "rc");
	assert(llvm_rc);
	llvm_build_rc_check(build_ctx, llvm_rc);
	if (!expr->op2) {
		tgt_reg_idx = build_ctx->tgt_reg_idx;
		assert(tgt_reg_idx > 0);
		sqlExprCacheStore(parse_ctx, csr, col, tgt_reg_idx);
	}
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
	case TK_COLUMN_REF:
		build_col_ref(ctx);
		return true;
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
		assert(expr->pLeft != NULL);
		return llvm_build_int(ctx, false);
	default:
		unreachable();
	}
}

static bool
llvm_compile_module(struct llvm_jit_ctx *ctx)
{
	assert(ctx);

	LLVMModuleRef m;
	LLVMOrcThreadSafeContextRef ts_ctx;
	LLVMOrcThreadSafeModuleRef tsm;
	LLVMOrcJITDylibRef jd;
	LLVMOrcResourceTrackerRef rt;
	LLVMErrorRef err;

	m = ctx->module;
	assert(m);
	ts_ctx = LLVMOrcCreateNewThreadSafeContext();
	assert(ts_ctx);
	tsm = LLVMOrcCreateNewThreadSafeModule(m, ts_ctx);
	assert(tsm);
	LLVMOrcDisposeThreadSafeContext(ts_ctx);
	ctx->module = NULL; /* ownership transferred to thread-safe module */
	assert(llvm_lljit);
	jd = LLVMOrcLLJITGetMainJITDylib(llvm_lljit);
	rt = ctx->rt = LLVMOrcJITDylibCreateResourceTracker(jd);
	assert(rt);
	/*
	 * NB: This does not actually compile code. That happens lazily the first
	 * time a symbol defined in the m is requested.
	 */
	err = LLVMOrcLLJITAddLLVMIRModuleWithRT(llvm_lljit, rt, tsm);
	if (err) {
		const char *err_msg;

		err_msg = llvm_get_err_msg(err);
		assert(err_msg);
		diag_set(ClientError, ER_LLVM_IR_COMPILATION, err_msg);
		return false;
	}
	ctx->compiled = true;
	return true;
}