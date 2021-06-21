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
#include "mem.h"
#include "vdbe_jit.h"

/**
 * These functions are called during execution of jitted code.
 * TODO: consider implementing them in terms of LLVM bitcode.
 */
int
jit_mem_binop_exec(struct Mem *lhs, struct Mem *rhs, int op, struct Mem *output)
{
	assert(lhs != NULL);
	assert(rhs != NULL);
	assert(output != NULL);
	int ret;
	switch (op) {
	case ADD:
		ret = mem_add(lhs, rhs, output);
		break;
	case SUB:
		ret = mem_sub(lhs, rhs, output);
		break;
	case MUL:
		ret = mem_mul(lhs, rhs, output);
		break;
	case DIV:
		ret = mem_div(lhs, rhs, output);
		break;
	default:
		unreachable();
	}

	return ret;
}

int
jit_mem_cmp_exec(struct Mem *lhs, struct Mem *rhs, int cmp, struct Mem *output)
{
	assert(lhs != NULL);
	assert(rhs != NULL);
	assert(output != NULL);

	if (lhs->type == MEM_TYPE_NULL || rhs->type == MEM_TYPE_NULL) {
		output->type = MEM_TYPE_NULL;
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


	int v1;    /* Left operand:  0==FALSE, 1==TRUE, 2==UNKNOWN or NULL */
	int v2;    /* Right operand: 0==FALSE, 1==TRUE, 2==UNKNOWN or NULL */

	if (mem_is_null(lhs)) {
		v1 = 2;
	} else if (mem_is_bool(lhs)) {
		v1 = lhs->u.b;
	} else {
		diag_set(ClientError, ER_SQL_TYPE_MISMATCH,
			 mem_str(lhs), "boolean");
		return -1;
	}
	if (mem_is_null(rhs)) {
		v2 = 2;
	} else if (mem_is_bool(rhs)) {
		v2 = rhs->u.b;
	} else {
		diag_set(ClientError, ER_SQL_TYPE_MISMATCH,
			 mem_str(rhs), "boolean");
		return -1;
	}

	static const unsigned char and_logic[] = { 0, 0, 0, 0, 1, 2, 0, 2, 2 };
	static const unsigned char or_logic[] = { 0, 1, 2, 1, 1, 1, 2, 1, 2 };
	switch (predicate) {
	case AND:
		v1 = and_logic[v1*3+v2];
		break;
	case OR:
		v1 = or_logic[v1*3+v2];
		break;
	default:
		unreachable();
	}
	mem_set_null(output);
	if (v1 != 2)
		mem_set_bool(output, v1);
	return 0;
}

int
jit_mem_concat_exec(struct Mem *lhs, struct Mem *rhs, int unused,
		    struct Mem *output)
{
	(void) unused;
	if ((lhs->type != MEM_TYPE_STR && lhs->type != MEM_TYPE_BIN) ||
    (rhs->type != MEM_TYPE_STR && rhs->type != MEM_TYPE_BIN)) {
		char *inconsistent_type = (lhs->type & (MEM_TYPE_STR | MEM_TYPE_BIN)) == 0 ?
					  mem_type_to_str(lhs) :
					  mem_type_to_str(rhs);
		diag_set(ClientError, ER_INCONSISTENT_TYPES, "TEXT or BLOB",
			 inconsistent_type);
		return -1;
	}
	if (mem_concat(lhs, rhs, output) != 0) {
	    return -1;
	}
	return 0;
}

int
jit_agg_max_exec(struct Mem *best, struct Mem *current)
{
	assert(best != NULL && current != NULL);
	if (best->flags != 0) {
		int cmp = sqlMemCompare(best, current, NULL);
		if (cmp < 0)
		    mem_copy(best, current);
	} else {
		best->db = sql_get();
		mem_copy(best, current);
	}
	return 0;
}

int
jit_agg_count_exec(struct Mem *count, struct Mem *current)
{
	if (count->flags == 0) {
		count->u.i = 0;
		count->type = MEM_TYPE_INT;
	}
	if (current->type != MEM_TYPE_NULL)
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
	if (current->type != MEM_TYPE_NULL) {
		if (current->type == MEM_TYPE_INT) {
			if (sum->type == MEM_TYPE_INT)
				sum->u.i += current->u.i;
			else if (sum->type == MEM_TYPE_DOUBLE)
				sum->u.r += current->u.i;
		} else if (current->type == MEM_TYPE_DOUBLE) {
			if (sum->type == MEM_TYPE_INT) {
				sum->u.r += sum->u.i + current->u.r;
				sum->flags = MEM_TYPE_DOUBLE;
			} else if (sum->flags == MEM_TYPE_DOUBLE)
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
	if (mem_from_mp_ephemeral(output, field, &unused) != 0)
		return -1;
	return 1;
}

void
jit_debug_print(const char *msg)
{
	say_debug("%s", msg);
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
	return port_c_add_tuple(port, tuple);
error:
	region_truncate(region, svp);
	return -1;
}
