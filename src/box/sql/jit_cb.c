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
#include "box/tuple.h"
#include "box/port.h"

#include "sqlInt.h"
#include "vdbe_jit.h"

/**
 * These functions are called during execution of jitted code.
 * TODO: consider implementing them in terms of LLVM bitcode.
 */
int
jit_mem_binop_exec(struct Mem *lhs, struct Mem *rhs, int op, struct Mem *output)
{
	assert(output != NULL);
	int lhs_mem_type = lhs->flags & MEM_PURE_TYPE_MASK;
	int rhs_mem_type = rhs->flags & MEM_PURE_TYPE_MASK;

	if (lhs_mem_type == MEM_Null || rhs_mem_type == MEM_Null) {
		output->flags = MEM_Null;
		output->u.i = 0;
		return 0;
	}

	if ((lhs_mem_type != MEM_Int && lhs_mem_type != MEM_Real) ||
	    (rhs_mem_type != MEM_Int && rhs_mem_type != MEM_Real)) {
		diag_set(ClientError, ER_JIT_EXECUTION, "attempt at providing "\
			 "arithmetic operation on non-numeric values");
		return -1;
	}

	if (lhs_mem_type == MEM_Int && rhs_mem_type == MEM_Int) {
		output->flags = MEM_Int;
		switch (op) {
			case ADD: output->u.i = lhs->u.i + rhs->u.i; break;
			case SUB: output->u.i = lhs->u.i - rhs->u.i; break;
			case MUL: output->u.i = lhs->u.i * rhs->u.i; break;
			case DIV:
				if (rhs->u.i == 0) {
					diag_set(ClientError, ER_JIT_EXECUTION,
						 "division by zero");
					return -1;
				}
				output->u.i = lhs->u.i / rhs->u.i;
				break;
			default: unreachable();
		}
		return 0;
	}
	double f_lhs = lhs_mem_type == MEM_Real ? lhs->u.r : lhs->u.i;
	double f_rhs = rhs_mem_type == MEM_Real ? rhs->u.r : rhs->u.i;
	switch (op) {
		case ADD: output->u.r = f_lhs + f_rhs; break;
		case SUB: output->u.r = f_lhs - f_rhs; break;
		case MUL: output->u.r = f_lhs * f_rhs; break;
		case DIV:
			if (f_rhs == (double) 0) {
				diag_set(ClientError, ER_JIT_EXECUTION,
					 "division by zero");
				return -1;
			}
			output->u.r = f_lhs / f_rhs;
			break;
		default: unreachable();
	}

	output->flags = MEM_Real;
	return 0;
}

int
jit_mem_cmp_exec(struct Mem *lhs, struct Mem *rhs, int cmp, struct Mem *output)
{
	assert(output != NULL);
	int lhs_mem_type = lhs->flags & MEM_PURE_TYPE_MASK;
	int rhs_mem_type = rhs->flags & MEM_PURE_TYPE_MASK;

	if (lhs_mem_type == MEM_Null || rhs_mem_type == MEM_Null) {
		output->flags = MEM_Null;
		output->u.i = 0;
		return 0;
	}

	int res_cmp = sqlMemCompare(lhs, rhs, NULL);
	int res;
	switch (cmp) {
		case LT: res = res_cmp < 0; break;
		case LE: res = res_cmp <= 0; break;
		case GT: res = lhs->u.i > rhs->u.i; break;
		case GE: res = lhs->u.i >= rhs->u.i; break;
		case EQ: res = res_cmp == 0; break;
		case NE: res = res_cmp != 0; break;
		default: unreachable();
	}
	mem_set_bool(output, res);
	return 0;
}

int
jit_mem_predicate_exec(struct Mem *lhs, struct Mem *rhs, int predicate,
		       struct Mem *output)
{
	assert(output != NULL);
	int lhs_mem_type = lhs->flags & MEM_PURE_TYPE_MASK;
	int rhs_mem_type = rhs->flags & MEM_PURE_TYPE_MASK;

	/* 0 == FALSE, 1 == TRUE, 2 == NULL */
	int v1, v2;

	if ((lhs_mem_type & MEM_Null) != 0) {
		v1 = 2;
	} else if ((lhs_mem_type & MEM_Int) != 0) {
		v1 = lhs->u.i != 0;
	} else {
		diag_set(ClientError, ER_SQL_TYPE_MISMATCH,
			 sql_value_text(lhs), "integer");
		return -1;
	}
	if ((rhs_mem_type & MEM_Null) != 0) {
		v2 = 2;
	} else if ((rhs_mem_type & MEM_Int) != 0) {
		v2 = rhs->u.i != 0;
	} else {
		diag_set(ClientError, ER_SQL_TYPE_MISMATCH,
			 sql_value_text(rhs), "integer");
		return -1;
	}
	static const unsigned char and_table[] = { 0, 0, 0, 0, 1, 2, 0, 2, 2 };
	static const unsigned char or_table[] = { 0, 1, 2, 1, 1, 1, 2, 1, 2 };

	if (predicate == AND)
		v1 = and_table[v1 * 3 + v2];
	if (predicate == OR)
		v1 = or_table[v1 * 3 + v2];
	if (v1 == 2) {
		output->flags = MEM_Null;
	} else {
		output->u.i = v1;
		output->flags = MEM_Int;
	}
	return 0;
}

int
jit_mem_concat_exec(struct Mem *lhs, struct Mem *rhs, int unused,
		    struct Mem *output)
{
	(void) unused;
	uint32_t str_type_p1 = lhs->flags & (MEM_Blob | MEM_Str);
	uint32_t str_type_p2 = rhs->flags & (MEM_Blob | MEM_Str);
	if (str_type_p1 == 0 || str_type_p2 == 0) {
		char *inconsistent_type = str_type_p1 == 0 ?
					  mem_type_to_str(lhs) :
					  mem_type_to_str(rhs);
		diag_set(ClientError, ER_INCONSISTENT_TYPES, "TEXT or BLOB",
			 inconsistent_type);
		return -1;
	}
	uint32_t total_len = lhs->n + rhs->n;
	if (sqlVdbeMemGrow(output, total_len + 2, output == rhs)) {
		diag_set(OutOfMemory, total_len + 2, "sql malloc", "mem");
		return -1;
	}
	if (lhs->flags & MEM_Str)
		MemSetTypeFlag(output, MEM_Str);
	else
		MemSetTypeFlag(output, MEM_Blob);
	if (output != rhs) {
		memcpy(output->z, rhs->z, rhs->n);
	}
	memcpy(&output->z[rhs->n], lhs->z, lhs->n);
	output->z[total_len]=0;
	output->z[total_len + 1] = 0;
	output->flags |= MEM_Term;
	output->n = (int) total_len;
	return 0;
}

int
jit_agg_max_exec(struct Mem *best, struct Mem *current)
{
	assert(best != NULL && current != NULL);
	if (best->flags != 0) {
		int cmp = sqlMemCompare(best, current, NULL);
		if (cmp < 0)
			sqlVdbeMemCopy(best, current);
	} else {
		best->db = sql_get();
		sqlVdbeMemCopy(best, current);
	}
	return 0;
}

int
jit_agg_count_exec(struct Mem *count, struct Mem *current)
{
	if (count->flags == 0) {
		count->u.i = 0;
		count->flags = MEM_Int;
	}
	if ((current->flags & MEM_Null) == 0)
		count->u.i++;
	return 0;
}

int
jit_agg_sum_exec(struct Mem *sum, struct Mem *current)
{
	if (sum->flags == 0) {
		sum->flags = current->flags;
		sum->u = current->u;
		return 0;
	}
	if ((current->flags & MEM_Null) == 0) {
		if ((current->flags & MEM_Int) != 0) {
			if ((sum->flags & MEM_Int) != 0)
				sum->u.i += current->u.i;
			else if ((sum->flags & MEM_Real) != 0)
				sum->u.r += current->u.i;
		} else if ((current->flags & MEM_Real) != 0) {
			if ((sum->flags & MEM_Int) != 0) {
				sum->u.r += sum->u.i + current->u.r;
				sum->flags = MEM_Real;
			} else if ((sum->flags & MEM_Real) != 0)
				sum->u.r += current->u.r;
		} else {
			diag_set(ClientError, ER_JIT_EXECUTION,
				 "attempt at providing addition on "
				 "non-numeric values");
			return -1;
		}
	}
	return 0;
}

int
jit_tuple_field_fetch(struct tuple *tuple, uint32_t fieldno, struct Mem *output)
{
	const char *data = tuple_data(tuple);
	mp_decode_array(&data);
	struct tuple_format *format = tuple_format(tuple);
	assert(fieldno < tuple_format_field_count(format));
	const char *field = tuple_field(tuple, fieldno);
	const char *end = field;
	mp_next(&end);
	uint32_t unused;
	if (vdbe_decode_msgpack_into_mem(field, output, &unused) != 0)
		return -1;
	return 1;
}

void
jit_debug_print(const char *msg)
{
	say_debug(msg);
}

extern int
jit_iterator_next(struct iterator *iter, struct tuple *output, int *status)
{
	assert(output != NULL);
	if (iterator_next(iter, &output) != 0)
		return -1;
	if (output != NULL) {
		*status = 0;
	} else {
		*status = 1;
	}
	return 0;
}

int
jit_mem_to_port(struct Mem *mem, int mem_count, struct port *port)
{
	assert(mem_count > 0);
	size_t size = mp_sizeof_array(mem_count);
	struct region *region = &fiber()->gc;
	size_t svp = region_used(region);
	char *pos = (char *) region_alloc(region, size);
	if (pos == NULL) {
		diag_set(OutOfMemory, size, "region_alloc", "SQL row");
		return -1;
	}
	mp_encode_array(pos, mem_count);
	uint32_t unused;
	for (int i = 0; i < mem_count; ++i) {
		if (sql_vdbe_mem_encode_tuple(mem, mem_count, &unused,
					      region) != 0)
			goto error;
	}
	size = region_used(region) - svp;
	pos = (char *) region_join(region, size);
	if (pos == NULL) {
		diag_set(OutOfMemory, size, "region_join", "pos");
		goto error;
	}
	struct tuple *tuple =
		tuple_new(box_tuple_format_default(), pos, pos + size);
	if (tuple == NULL)
		goto error;
	region_truncate(region, svp);
	return port_tuple_add(port, tuple);
error:
	region_truncate(region, svp);
	return -1;
}
