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
#include "assoc.h"
#include "box/tuple.h"
#include "box/port.h"

#include "sqlInt.h"
#include "vdbe_jit.h"

/** Heador for IR building and ORC JIT support. */
#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/OrcBindings.h"
#include "llvm-c/Support.h"

/** Headers responsible for ptimization passes. */
#include "llvm-c/Transforms/Utils.h"
#include "llvm-c/Transforms/IPO.h"
#include "llvm-c/Transforms/PassManagerBuilder.h"

/** Global variables to represent types in JIT. */
LLVMTypeRef v_mem;
LLVMTypeRef v_tuple;

static struct load_type {
	const char *name;
	LLVMTypeRef *type;
} load_types[] = {
	{ "t_mem", &v_mem },
	{ "t_tuple", &v_tuple },
};

/** Extern functions available during execution of jitted code. */
LLVMValueRef f_memcpy;
LLVMValueRef f_tuple_fetch;
LLVMValueRef f_mem_binop_exec;
LLVMValueRef f_mem_cmp_exec;
LLVMValueRef f_mem_predicate_exec;
LLVMValueRef f_mem_concat_exec;
LLVMValueRef f_agg_max_exec;
LLVMValueRef f_agg_count_exec;
LLVMValueRef f_agg_sum_exec;
LLVMValueRef f_mem_to_port;
LLVMValueRef f_debug_print;

static struct load_function {
	const char *name;
	void *func;
	LLVMValueRef *ref;
} load_funs[] = {
	{
		"memcpy",
		memcpy,
		&f_memcpy
	},
	{
		"jit_tuple_field_fetch",
		jit_tuple_field_fetch,
		&f_tuple_fetch
	},
	{
		"jit_mem_binop_exec",
		jit_mem_binop_exec,
		&f_mem_binop_exec
	},
	{
		"jit_mem_cmp_exec",
		jit_mem_cmp_exec,
		&f_mem_cmp_exec
	},
	{
		"jit_mem_predicate_exec",
		jit_mem_predicate_exec,
		&f_mem_predicate_exec
	},
	{
		"jit_mem_concat_exec",
		jit_mem_concat_exec,
		&f_mem_concat_exec
	},
	{
		"jit_agg_max_exec",
		jit_agg_max_exec,
		&f_agg_max_exec
	},
	{
		"jit_agg_count_exec",
		jit_agg_count_exec,
		&f_agg_count_exec
	},
	{
		"jit_agg_sum_exec",
		jit_agg_sum_exec,
		&f_agg_sum_exec
	},
};

/** Target machine specification. */
const char *target_layout = NULL;
const char *target_triple = NULL;

/** ORC dependent global info. */
LLVMOrcJITStackRef orc_jit = NULL;
LLVMTargetMachineRef target_machine = NULL;

static LLVMTypeRef
jit_load_type(LLVMModuleRef module, const char *var_name)
{
	LLVMValueRef value = LLVMGetNamedGlobal(module, var_name);
	if (value == NULL) {
		say_error("failed to find global variable: %s", var_name);
		return NULL;
	}
	LLVMTypeRef type = LLVMTypeOf(value);
	if (type == NULL) {
		say_error("unknown LLVM type for variable %s", var_name);
		return NULL;
	}
	return LLVMGetElementType(type);
}

static void
jit_orc_map_extern_funcs()
{
	for (uint32_t i = 0; i < lengthof(load_funs); ++i) {
		struct load_function f = load_funs[i];
		LLVMAddSymbol(f.name, f.func);
	}
}

static int
jit_load_external_types(LLVMModuleRef *module)
{
	/* FIXME: hardcoded path. */
	const char *path = "src/box/sql/jit_types.bc";
	LLVMMemoryBufferRef buf;
	char *error_msg;
	if (LLVMCreateMemoryBufferWithContentsOfFile(path, &buf,
						     &error_msg) != 0) {
		say_error(error_msg);
		return -1;
	}
	if (LLVMParseBitcode2(buf, module) != 0) {
		say_error("error during parsing pre-compiled IR");
		return -1;
	}
	LLVMDisposeMemoryBuffer(buf);

	/* Load types. */
	for (uint32_t i = 0; i < lengthof(load_types); ++i) {
		struct load_type t = load_types[i];
		*t.type = jit_load_type(*module, t.name);
		if (*t.type == NULL)
			return -1;
	}

	/* Load external function prototypes. */
	for (uint32_t i = 0; i < lengthof(load_funs); ++i) {
		struct load_function func = load_funs[i];
		*func.ref =  LLVMGetNamedFunction(*module, func.name);
		if (*func.ref == NULL) {
			say_error("failed to load %s function", func.name);
			return -1;
		}
	}
	jit_orc_map_extern_funcs();
	return 0;
}

/**
 * Firstly, we parse jit_types.bc once, load and save prototype
 * to global variables. Then, we create another module, for
 * which initially created function is not visible. But we can
 * add it to the new module using saved earlier prototype. If
 * we refer to the same function twice in a separate module,
 * we don't need to add it to that module again.
 */
static LLVMValueRef
jit_get_func_decl(LLVMModuleRef module, LLVMValueRef v_src)
{
	LLVMValueRef func =
		LLVMGetNamedFunction(module, LLVMGetValueName(v_src));
	if (func != NULL)
		return func;
	func = LLVMAddFunction(module, LLVMGetValueName(v_src),
			       LLVMGetElementType(LLVMTypeOf(v_src)));
	assert(func != NULL);
	return func;
}

int
llvm_init()
{
	assert(! sql_get()->vdbe_jit_init);
	LLVMInitializeNativeTarget();
	LLVMLinkInMCJIT();
	LLVMInitializeNativeAsmPrinter();
	LLVMInitializeNativeAsmParser();
	say_info("Initializing llvm submodule...");
	LLVMModuleRef boot_module;
	if (jit_load_external_types(&boot_module) != 0)
		return -1;
	LLVMTargetRef target;
	target_triple = LLVMGetTarget(boot_module);
	target_layout = LLVMGetDataLayoutStr(boot_module);
	char *error_msg;
	if (LLVMGetTargetFromTriple(target_triple, &target, &error_msg) != 0) {
		say_error(error_msg);
		LLVMDisposeMessage(error_msg);
		return -1;
	}
	if (! LLVMTargetHasJIT(target)) {
		say_error("Target machine doesn't support JIT."\
			 "Please, turn JIT option off.");
		return -1;
	}
	char *cpu_name = LLVMGetHostCPUName();
	char *cpu_features = LLVMGetHostCPUFeatures();
	say_info("LLVM JIT ver.%d detected CPU %s with features %s",
		 LLVM_VERSION_MAJOR, cpu_name, cpu_features);

	target_machine =
		LLVMCreateTargetMachine(target, target_triple, cpu_name,
					cpu_features, LLVMCodeGenLevelDefault,
					LLVMRelocDefault, LLVMCodeModelJITDefault);

	LLVMDisposeMessage(cpu_name);
	LLVMDisposeMessage(cpu_features);
	/* Force symbols in main binary to be loaded. */
	LLVMLoadLibraryPermanently(NULL);
	orc_jit = LLVMOrcCreateInstance(target_machine);
	if (orc_jit == NULL) {
		say_error("failed to create instance of ORC JIT");
		return -1;
	}

	sql_get()->vdbe_jit_init = true;
	return 0;
}

static LLVMModuleRef
jit_module_create()
{
	LLVMModuleRef module = LLVMModuleCreateWithName("VDBE_Module");
	if (module == NULL)
		return NULL;
	LLVMSetTarget(module, target_triple);
	LLVMSetDataLayout(module, target_layout);
	return module;
}

static void
jit_compile_context_init(struct jit_compile_context *context)
{
	context->module = jit_module_create();
	context->builder = LLVMCreateBuilder();
	context->func_count = 0;
	context->decoded_fields = mh_i32ptr_new();
	context->func_ctx = (struct jit_func_context *)
		((char *) context + sizeof(struct jit_compile_context));
	assert(context->func_ctx != NULL);
	memset(context->func_ctx, 0, sizeof(struct jit_compile_context));
}

struct jit_compile_context *
parse_get_jit_context(struct Parse *parse)
{
	if (parse->jit_context == NULL) {
		size_t sz = sizeof(struct jit_compile_context) +
			    sizeof(struct jit_func_context);
		parse->jit_context = region_alloc(&parse->region, sz);
		if (parse->jit_context == NULL) {
			diag_set(OutOfMemory, sz, "region",
				 "jit_context");
			parse->is_aborted = true;
			return NULL;
		}
		jit_compile_context_init(parse->jit_context);
	}
	return parse->jit_context;
}

int
jit_expr_emit_start(struct jit_compile_context *context, uint32_t expr_count)
{
	LLVMTypeRef param_types[] = { LLVMPointerType(v_tuple, 0),
				      LLVMPointerType(v_mem, 0) };
	LLVMTypeRef func_type = LLVMFunctionType(LLVMInt8Type(), param_types,
						 2, false);
	const char *name = (char *) tt_sprintf("expr_%d", context->func_count++);
	size_t name_len = strlen(name) + 1;
	context->func_ctx->name = region_alloc(&fiber()->gc, name_len);
	if (context->func_ctx->name == NULL) {
		diag_set(OutOfMemory, name_len, "region", "name");
		return -1;
	}
	memcpy(context->func_ctx->name, name, name_len);
	context->func_ctx->name[name_len - 1] = '\0';
	LLVMValueRef func = LLVMAddFunction(context->module, name, func_type);
	LLVMSetLinkage(func, LLVMExternalLinkage);
	LLVMSetVisibility(func, LLVMDefaultVisibility);
	LLVMBasicBlockRef entry_bb = LLVMAppendBasicBlock(func, "entry");
	LLVMPositionBuilderAtEnd(context->builder, entry_bb);
	size_t sz = sizeof(LLVMValueRef) * expr_count;
	context->func_ctx->output_args = region_alloc(&fiber()->gc, sz);
	if (context->func_ctx->output_args == NULL) {
		diag_set(OutOfMemory, sz, "region", "output_args");
		return -1;
	}
	context->func_ctx->tuple = LLVMGetParam(func, 0);
	LLVMValueRef output_mem_array = LLVMGetParam(func, 1);
	for (uint32_t i = 0; i < expr_count; ++i) {
		LLVMValueRef idx = LLVMConstInt(LLVMInt32Type(), i, false);
		context->func_ctx->output_args[i] =
			LLVMBuildGEP(context->builder, output_mem_array, &idx,
				     1, tt_sprintf("ouput_mem_%d", i));
	}
	context->func_ctx->func = func;
	return 0;
}

int
jit_expr_emit_finish(struct jit_compile_context *context)
{
	assert(context != NULL);
	char *error_msg = NULL;
	LLVMBuildRet(context->builder, LLVMConstInt(LLVMInt8Type(), 0, 0));
	if (LLVMVerifyFunction(context->func_ctx->func,
			       LLVMPrintMessageAction) != 0) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "function IR verification has failed");
		LLVMDisposeMessage(error_msg);
		return -1;
	}
	//char *module_str = LLVMPrintModuleToString(context->module);
	//say_info("LLVM module IR: %s", module_str);
	//LLVMDisposeMessage(module_str);
	if (LLVMVerifyModule(context->module, LLVMReturnStatusAction,
			     &error_msg) != 0) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION, error_msg);
		LLVMDisposeMessage(error_msg);
		return -1;
	}
	mh_i32ptr_clear(context->decoded_fields);
	return 0;
}

/**
 * This function saves literal to the given struct Mem.
 */
static void
jit_value_store_to_mem(struct jit_compile_context *context, LLVMValueRef value,
		       int type, LLVMValueRef mem)
{
	LLVMBuilderRef builder = context->builder;
	LLVMValueRef union_ptr = NULL;
	if ((type & MEM_Str) != 0) {
		union_ptr = LLVMBuildStructGEP(builder, mem, 4, "Mem->z");
		value = LLVMBuildBitCast(builder, value,
					 LLVMPointerType(LLVMIntType(8), 0), "str");
	} else {
		/*
		 * LLVM doesn't support accessing union fields, so we
		 * must provide cast.
		 */
		LLVMTypeRef value_type = LLVMPointerType(LLVMTypeOf(value), 0);
		union_ptr = LLVMBuildBitCast(builder, mem, value_type, "Mem->u");
	}
	LLVMBuildStore(builder, value, union_ptr);
	/* Also we should set type flag in struct Mem. */
	LLVMValueRef flags_ptr = LLVMBuildStructGEP(builder, mem, 1, "Mem->flags");
	LLVMValueRef mem_type_val = LLVMConstInt(LLVMInt32Type(), type, false);
	LLVMBuildStore(builder, mem_type_val, flags_ptr);
}

static void
jit_build_mem_copy(struct jit_compile_context *context, LLVMValueRef from,
		   LLVMValueRef to)
{
	assert(LLVMTypeOf(from) == LLVMTypeOf(to));
	/*
	 * Code below implements call of memcpy. @from and @to are
	 * of type struct Mem *. Since LLVM IR doesn't tolerate
	 * mismatch of argument types, explicit cast is required.
	 * char *from_i8 = (char *) from;
	 * char *to_i8 = (char * ) to;
	 * memcpy(to_i8, from_i8, sizeof(struct Mem));
	 */
	LLVMBuilderRef builder = context->builder;
	LLVMTypeRef ptr_type = LLVMPointerType(LLVMInt8Type(), 0);
	LLVMValueRef from_i8 = LLVMBuildBitCast(builder, from, ptr_type,
						"from_i8");
	LLVMValueRef to_i8 = LLVMBuildBitCast(builder, to, ptr_type, "to_i8");
	/* Copy only meaningful part of the struct. */
	LLVMValueRef len = LLVMConstInt(LLVMIntType(64),
					offsetof(struct Mem, zMalloc), false);
	LLVMValueRef args[] = { to_i8, from_i8, len };
	LLVMValueRef memcpy = jit_get_func_decl(context->module, f_memcpy);
	LLVMBuildCall(builder, memcpy, args, lengthof(args), "memcpy");
}

static inline enum binop
tokenop_to_binop(int token)
{
	switch (token) {
		case TK_PLUS: return ADD;
		case TK_MINUS: return SUB;
		case TK_SLASH: return DIV;
		case TK_STAR: return MUL;
		default: unreachable();
	}
}

static inline enum cmpop
tokenop_to_cmpop(int token)
{
	switch (token) {
		case TK_LT: return LT;
		case TK_LE: return LE;
		case TK_GT: return GT;
		case TK_GE: return GE;
		case TK_EQ: return EQ;
		case TK_NE: return NE;
		default: unreachable();
	}
}

static inline enum predicate
tokenop_to_predicate(int token)
{
	switch (token) {
		case TK_AND: return AND;
		case TK_OR: return OR;
		default: unreachable();
	}
}

static void
jit_build_result_check(struct jit_compile_context *context, LLVMValueRef result)
{
	assert(LLVMGetTypeKind(LLVMTypeOf(result)) == LLVMIntegerTypeKind);
	/*
	 * @result usually is return code from funtion call.
	 * We obey convention that in case of fail function
	 * returns != 0 return code. So this code checks
	 * whether function finished without errors or not.
	 * If the latter, return from jitted function with
	 * same error code. Bitcode below implements C code:
	 * if (result != 0) {
	 * 	return result;
	 * }
 	*/
	LLVMBuilderRef builder = context->builder;
	LLVMValueRef zero = LLVMConstInt(LLVMInt32Type(), 0, false);
	LLVMValueRef cmp_res = LLVMBuildICmp(builder, LLVMIntNE, result,
					     zero, "cmp");
	LLVMBasicBlockRef current_bb = LLVMGetInsertBlock(builder);
	/* Construct THEN basic block consisting of return 0 instr. */
	LLVMBasicBlockRef then_bb = LLVMAppendBasicBlock(context->func_ctx->func,
							 "if-then");
	LLVMPositionBuilderAtEnd(builder, then_bb);
	result = LLVMBuildTrunc(builder, result, LLVMInt8Type(), "res_i8");
	LLVMBuildRet(builder, result);
	LLVMBasicBlockRef else_bb = LLVMAppendBasicBlock(context->func_ctx->func,
							 "if-else");
	LLVMPositionBuilderAtEnd(builder, current_bb);
	LLVMBuildCondBr(builder, cmp_res, then_bb, else_bb);
	LLVMPositionBuilderAtEnd(builder, else_bb);
}

/** Forward declaration. */
static LLVMValueRef
jit_expr_build_value(struct jit_compile_context *context, struct Expr *expr);

static LLVMValueRef
jit_expr_build_binop_call(struct jit_compile_context *context,
			  struct Expr *expr, int op, LLVMValueRef func)
{
	LLVMValueRef op_exec = jit_get_func_decl(context->module, func);
	if (op_exec == NULL) {
		diag_set(ClientError, ER_LLVM_IR_COMPILATION,
			 "error during function loading");
		return NULL;
	}
	LLVMValueRef lhs = jit_expr_build_value(context, expr->pLeft);
	if (lhs == NULL)
		return NULL;
	LLVMValueRef rhs = jit_expr_build_value(context, expr->pRight);
	if (rhs == NULL)
		return NULL;
	LLVMBuilderRef builder = context->builder;
	LLVMValueRef res = LLVMBuildAlloca(builder, v_mem, "func_res");
	LLVMValueRef op_val = LLVMConstInt(LLVMInt32Type(), op, false);
	LLVMValueRef args[] = { lhs, rhs, op_val, res };
	LLVMValueRef ret_val = LLVMBuildCall(builder, op_exec, args,
					     lengthof(args), "ret_val");
	jit_build_result_check(context, ret_val);
	return res;
}

static int64_t
expr_to_int(struct Expr *expr)
{
	assert(expr->op == TK_INTEGER);
	if (expr->flags & EP_IntValue) {
		int i = expr->u.iValue;
		assert(i >= 0);
		return i;
	}
	const char *z = expr->u.zToken;
	assert(z != NULL);
	return atoi(z);
}

static LLVMValueRef
jit_expr_build_value(struct jit_compile_context *context, struct Expr *expr)
{
	assert(expr != NULL);
	LLVMBuilderRef builder = context->builder;
	switch (expr->op) {
		case TK_PLUS:
		case TK_MINUS:
		case TK_STAR:
		case TK_SLASH: {
			enum binop op = tokenop_to_binop(expr->op);
			return jit_expr_build_binop_call(context, expr, op,
							 f_mem_binop_exec);
		}
		case TK_AND:
		case TK_OR: {
			enum predicate op = tokenop_to_predicate(expr->op);
			return jit_expr_build_binop_call(context, expr, op,
							 f_mem_predicate_exec);
		}
		case TK_LE:
		case TK_LT:
		case TK_GE:
		case TK_GT:
		case TK_NE:
		case TK_EQ: {
			enum cmpop op = tokenop_to_cmpop(expr->op);
			return jit_expr_build_binop_call(context, expr, op,
							 f_mem_cmp_exec);
		}
		case TK_TRUE:
		case TK_FALSE: {
			bool raw_value = expr->op == TK_TRUE;
			LLVMValueRef value = LLVMConstInt(LLVMInt64Type(),
							  raw_value, false);
			/* Allocate struct Mem on stack and save value inside it. */
			LLVMValueRef alloc =
				LLVMBuildAlloca(builder, v_mem, "const_bool_mem");
			jit_value_store_to_mem(context, value, MEM_Bool, alloc);
			return alloc;
		}
		case TK_INTEGER: {
			int64_t raw_value = expr_to_int(expr);
			LLVMValueRef value = LLVMConstInt(LLVMInt64Type(),
							  raw_value, false);
			/* Allocate struct Mem on stack and save value inside it. */
			LLVMValueRef alloc =
				LLVMBuildAlloca(builder, v_mem, "const_int_mem");
			jit_value_store_to_mem(context, value, MEM_Int, alloc);
			return alloc;
		}
		case TK_FLOAT: {
			LLVMValueRef alloc =
				LLVMBuildAlloca(builder, v_mem, "const_float_mem");
			LLVMValueRef value = LLVMConstRealOfString(LLVMDoubleType(),
								   expr->u.zToken);
			jit_value_store_to_mem(context, value, MEM_Real, alloc);
			return alloc;
		}
		case TK_STRING: {
			LLVMValueRef alloc =
				LLVMBuildAlloca(builder, v_mem, "const_str_mem");
			LLVMValueRef str_len = LLVMConstInt(LLVMInt32Type(),
							    strlen(expr->u.zToken),
							    false);
			LLVMValueRef n = LLVMBuildStructGEP(builder, alloc, 3, "Mem->n");
			LLVMBuildStore(builder, str_len, n);
			LLVMValueRef str_ptr =
				LLVMBuildGlobalStringPtr(builder, expr->u.zToken, "str");
			jit_value_store_to_mem(context, str_ptr,
					       MEM_Static | MEM_Term | MEM_Str,
					       alloc);
			return alloc;
		}
		case TK_COLUMN:
		case TK_AGG_COLUMN: {
			struct mh_i32ptr_t *h = context->decoded_fields;
			uint32_t fieldno = expr->iColumn;
			/* To avoid decoding the same field twice we use hash. */
			mh_int_t k = mh_i32ptr_find(h, fieldno, NULL);
			if (k != mh_end(h))
				return mh_i32ptr_node(h, k)->val;
			LLVMValueRef tuple_fetch =
				jit_get_func_decl(context->module, f_tuple_fetch);
			if (tuple_fetch == NULL) {
				diag_set(ClientError, ER_LLVM_IR_COMPILATION,
					 "function's declaration is missing");
				return NULL;
			}
			/* Load field number into memory. */
			LLVMValueRef fieldno_val =
				LLVMConstInt(LLVMInt32Type(), fieldno, false);
			LLVMValueRef output =
				LLVMBuildAlloca(builder, v_mem, "decoded_field_mem");
			LLVMValueRef args[] = { context->func_ctx->tuple,
						fieldno_val, output };
			LLVMValueRef res =
				LLVMBuildCall(builder, tuple_fetch, args,
					      lengthof(args), "tuple_decode");
			assert(res != NULL);
			struct mh_i32ptr_node_t node = { fieldno, output };
			struct mh_i32ptr_node_t *old_node = NULL;
			if (mh_i32ptr_put(h, &node, &old_node, NULL) == mh_end(h)) {
				diag_set(OutOfMemory, 0, "mh_i32ptr_put",
					 "mh_i32ptr_node_t");
				return NULL;
			}
			assert(old_node == NULL);
			return output;
		}
		case TK_UNKNOWN:
		case TK_NULL: {
			LLVMValueRef alloc_mem =
				LLVMBuildAlloca(builder, v_mem, "null_mem");
			LLVMValueRef flags =
				LLVMBuildStructGEP(builder, alloc_mem, 1, "flags");
			LLVMValueRef null_type =
				LLVMConstInt(LLVMInt32Type(), MEM_Null, false);
			LLVMBuildStore(builder, null_type, flags);
			return alloc_mem;
		}
		case TK_UMINUS: {
			struct Expr *lhs = expr->pLeft;
			LLVMValueRef value = NULL;
			int mem_flags = 0;
			if (lhs->op == TK_INTEGER) {
				int64_t raw_value = expr_to_int(expr->pLeft);
				value = LLVMConstInt(LLVMInt64Type(),
						     -raw_value, false);
				mem_flags = MEM_Int;
			} else if (lhs->op == TK_FLOAT) {
				double raw_value = atof(expr->pLeft->u.zToken);
				value = LLVMConstReal(LLVMDoubleType(),
						      -raw_value);
				mem_flags = MEM_Real;
			} else {
				struct Expr zero;
				zero.flags = EP_IntValue | EP_TokenOnly;
				zero.u.iValue = 0;
				zero.op = TK_INTEGER;
				struct Expr sub;
				sub.pLeft = &zero;
				sub.pRight = lhs;
				sub.op = TK_MINUS;
				return jit_expr_build_value(context, &sub);
			}
			LLVMValueRef alloc = LLVMBuildAlloca(builder, v_mem,
							     "const_uval_mem");
			jit_value_store_to_mem(context, value, mem_flags, alloc);
			return alloc;
		}
		case TK_CONCAT: {
			/*
			 * FIXME: jit_mem_concat_exec() allocates memory
			 * using sqlDbMalloc(). We must free it at the
			 * end of execution. To do so we must set MEM_Dyn
			 * flag and zMalloc field.
			 */
			return jit_expr_build_binop_call(context, expr, 0,
							 f_mem_concat_exec);
		}
		default: {
			diag_set(ClientError, ER_LLVM_IR_COMPILATION,
				  "unsupported expression type");
			return NULL;
		}
	}
}

//static int
//vdbe_jit_emit_expr_dump(struct jit_context *context)
//{
//	LLVMGetFu
//}

/** @expr is supposed to be one of AND'ed terms from WHERE clause. */
static void
jit_build_cond_return(struct jit_compile_context *context, LLVMValueRef res)
{
	/*
	 * Get value of the result. If it's 0 (false), return from
	 * function calculating predicate since it one of AND
	 * operands. Bitcode below implements analogue of C code:
	 * if (res->u.i == 0) {
	 * 	output->u.i = 0;
	 * 	return 0;
	 * }
	 */
	LLVMBuilderRef builder = context->builder;
	LLVMValueRef mem_union_int =
		LLVMBuildBitCast(builder, res,
				 LLVMPointerType(LLVMIntType(32), 0), "Mem->u.i");
	LLVMValueRef predicate_res = LLVMBuildLoad(builder, mem_union_int,
						   "predicate_res");
	LLVMValueRef zero = LLVMConstInt(LLVMInt32Type(), 0, false);
	LLVMValueRef cmp_res = LLVMBuildICmp(builder, LLVMIntEQ, predicate_res,
					     zero, "cmp");
	LLVMBasicBlockRef current_bb = LLVMGetInsertBlock(builder);
	LLVMBasicBlockRef then_bb = LLVMAppendBasicBlock(context->func_ctx->func,
							 "if-then");
	LLVMPositionBuilderAtEnd(builder, then_bb);
	/* Before return, save result of predicate (false) to output mem. */
	jit_build_mem_copy(context, res, context->func_ctx->output_args[0]);
	zero = LLVMBuildTrunc(builder, zero, LLVMInt8Type(), "res_i8");
	LLVMBuildRet(builder, zero);
	LLVMBasicBlockRef else_bb = LLVMAppendBasicBlock(context->func_ctx->func,
							 "if-else");
	LLVMPositionBuilderAtEnd(builder, current_bb);
	LLVMBuildCondBr(builder, cmp_res, then_bb, else_bb);
	LLVMPositionBuilderAtEnd(builder, else_bb);
}

int
jit_emit_expr(struct jit_compile_context *context, struct Expr *expr,
	      uint32_t expr_no)
{
	LLVMValueRef res = jit_expr_build_value(context, expr);
	if (res == NULL)
		return -1;
	/* Decide what to do with the result of calculation. */
	switch (context->func_ctx->strategy) {
		case COMPILE_EXPR_RS:
			/* Copy result to the output memory cell. */
			jit_build_mem_copy(context, res,
					   context->func_ctx->output_args[expr_no]);
			break;
		case COMPILE_EXPR_WHERE_COND:
			jit_build_cond_return(context, res);
			break;
		case COMPILE_EXPR_AGG:
			context->func_ctx->result = res;
			break;
		default: unreachable();
	}
	return 0;
}

static LLVMValueRef
agg_func_by_name(const char *name)
{
	if (strcmp("max", name) == 0)
		return f_agg_max_exec;
	if (strcmp("count", name) == 0)
		return f_agg_count_exec;
	if (strcmp("sum", name) == 0)
		return f_agg_sum_exec;
//	if (strcmp("avg", name) == 0)
//		return f_agg_avg_exec;
	diag_set(ClientError, ER_LLVM_IR_COMPILATION,
		 tt_sprintf("aggregate with named %s doesn't exist", name));
	return NULL;
}

int
jit_emit_agg(struct jit_compile_context *context, const char *agg_name)
{
	LLVMBuilderRef builder = context->builder;
	LLVMValueRef agg_var = agg_func_by_name(agg_name);
	if (agg_var == NULL)
		return -1;
	LLVMValueRef agg_decl = jit_get_func_decl(context->module, agg_var);
	LLVMValueRef args[] = { context->func_ctx->output_args[0],
				context->func_ctx->result };
	LLVMValueRef ret_val = LLVMBuildCall(builder, agg_decl, args,
					     lengthof(args), "ret_val");
	jit_build_result_check(context, ret_val);
	return 0;
}

/** Set of lightweight IR optimizations. */
static void
jit_module_optimize(LLVMModuleRef module)
{
	LLVMPassManagerBuilderRef builder =  LLVMPassManagerBuilderCreate();
	LLVMPassManagerBuilderSetOptLevel(builder, 1); /* 1 means smth like O1 */
	/* Function level optimizations. */
	LLVMPassManagerRef func_pass =
		LLVMCreateFunctionPassManagerForModule(module);
	LLVMAddPromoteMemoryToRegisterPass(func_pass);
	LLVMPassManagerBuilderPopulateFunctionPassManager(builder, func_pass);
	LLVMInitializeFunctionPassManager(func_pass);
	for (LLVMValueRef func = LLVMGetFirstFunction(module); func != NULL;
	     func = LLVMGetNextFunction(func))
		LLVMRunFunctionPassManager(func_pass, func);
	LLVMFinalizeFunctionPassManager(func_pass) ;
	LLVMDisposePassManager(func_pass);
	/* Interprocedural optimizations: inlining. */
	LLVMPassManagerRef module_pass = LLVMCreatePassManager();
	LLVMPassManagerBuilderPopulateModulePassManager(builder, module_pass);
	LLVMAddAlwaysInlinerPass(module_pass);
	LLVMRunPassManager(module_pass, module);
	LLVMPassManagerBuilderDispose(builder);
}

void
jit_compile_context_release(struct jit_compile_context *context)
{
	if (context == NULL)
		return;
	mh_i32ptr_delete(context->decoded_fields);
	LLVMDisposeBuilder(context->builder);
	/* Context itself is allocated using region. */
}

void
jit_execute_context_release(struct jit_execute_context *context)
{
	if (context == NULL)
		return;
	if (context->jit_impl == LLVM_JIT_ORC && context->is_compiled)
		LLVMOrcRemoveModule(orc_jit, context->module_handle);
	else
		LLVMDisposeModule(context->module);
	free(context);
}

static void
jit_mc_map_extern_funcs(LLVMExecutionEngineRef engine)
{
	for (uint32_t i = 0; i < lengthof(load_funs); ++i) {
		struct load_function f = load_funs[i];
		LLVMAddGlobalMapping(engine, *f.ref, f.func);
	}
}

int
jit_mc_engine_prepare(struct jit_execute_context *context,
		      LLVMExecutionEngineRef *engine)
{
	assert(engine != NULL);
	char *error_msg = NULL;
	if (LLVMVerifyModule(context->module, LLVMReturnStatusAction,
			     &error_msg) != 0) {
		diag_set(ClientError, ER_JIT_EXECUTION, error_msg);
		LLVMDisposeMessage(error_msg);
		return -1;
	}
	jit_module_optimize(context->module);
	if (LLVMCreateExecutionEngineForModule(engine, context->module,
					       &error_msg) != 0) {
		diag_set(ClientError, ER_JIT_EXECUTION, error_msg);
		LLVMDisposeMessage(error_msg);
		return -1;
	}
	jit_mc_map_extern_funcs(*engine);
	return 0;
}

int
jit_mc_engine_finalize(struct jit_execute_context *context,
		       LLVMExecutionEngineRef engine)
{
	if (engine == NULL)
		return 0;
	if (context->is_compiled)
		return 0;
	char *error_msg = NULL;
	if (LLVMRemoveModule(engine, context->module, &context->module,
			     &error_msg) != 0) {
		diag_set(ClientError, ER_JIT_EXECUTION, error_msg);
		LLVMDisposeMessage(error_msg);
		return -1;
	}
	LLVMDisposeExecutionEngine(engine);
	LLVMDisposeMessage(error_msg);
	return 0;
}

static uint64_t
jit_symbol_resolve(const char *name, void *ctx)
{
	(void) ctx;
	/* MacOS mangles names with underscore. */
	if (name[0] == '_')
		name++;
	return (uint64_t) LLVMSearchForAddressOfSymbol(name);
}

static int
jit_orc_module_compile(struct jit_execute_context *context)
{
	assert(orc_jit != NULL);
	jit_module_optimize(context->module);
	LLVMOrcModuleHandle orc_handle;
	/*
	 * There are not so many conditional jumps, so it makes
	 * sense to compile whole module at once.
	 */
	if (LLVMOrcAddEagerlyCompiledIR(orc_jit, &orc_handle, context->module,
					jit_symbol_resolve, NULL) != 0) {
		diag_set(ClientError, ER_JIT_EXECUTION,
			 "failed to compile machine code");
		return -1;
	}
	context->module_handle = orc_handle;
	context->is_compiled = true;
	/* LLVMOrcAddEagerlyCompiledIR takes ownership of the module. */
	context->module = NULL;
	return 0;
}

int
jit_execute(struct jit_execute_context *context, struct tuple *tuple,
	    char *func_name, struct Mem *result)
{
	assert(result != NULL);
	if (context->jit_impl == LLVM_JIT_ORC && !context->is_compiled) {
		if (jit_orc_module_compile(context) != 0)
			return -1;
	}
	int (*func)(struct tuple *, struct Mem *) = NULL;
	if (context->jit_impl == LLVM_JIT_ORC) {
		LLVMOrcTargetAddress func_addr = 0;
		if (LLVMOrcGetSymbolAddressIn(orc_jit, &func_addr,
					      context->module_handle,
					      func_name) != 0 || func_addr == 0) {
			diag_set(ClientError, ER_JIT_EXECUTION,
				 tt_sprintf("can't find function %s", func_name));
			return -1;
		}
		func = (int (*)(struct tuple *, struct Mem *))func_addr;
	} else {
		assert(context->jit_impl == LLVM_JIT_MC);
		func = (int (*)(struct tuple *, struct Mem *))
			LLVMGetFunctionAddress(context->engine, func_name);
	}
	assert(func != NULL);
	return func(tuple, result);
}

extern int
jit_execute_with_dump(struct jit_execute_context *context, struct tuple *tuple,
		      struct port *port)
{
	assert(port != NULL);
	LLVMExecutionEngineRef engine;
	if (jit_mc_engine_prepare(context, &engine) != 0)
		return -1;
	int (*func)(struct tuple *, struct port *) =
	(int (*)(struct tuple *, struct port *))
		LLVMGetFunctionAddress(engine, "expr_eval_with_dump");
	int rc = func(tuple, port);
	assert(rc != 0);
	return rc;
}
