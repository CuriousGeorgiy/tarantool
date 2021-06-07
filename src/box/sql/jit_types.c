#ifndef TARANTOOL_SQL_JIT_TYPES_H_INCLUDED
#define TARANTOOL_SQL_JIT_TYPES_H_INCLUDED
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
#include "parse.h"
#include "sqlInt.h"
#include "mem.h"
#include "vdbe_jit.h"
#include "box/tuple.h"
#include "box/port.h"

/**
 * This source file is never linked, it's only purpose is
 * to generate bit-code containing all */

struct Mem t_mem;
struct tuple t_tuple;
struct iterator t_iterator;
struct port t_port;

void *referenced_functions[] =
{
	memcpy,
	jit_tuple_field_fetch,
	jit_mem_binop_exec,
	jit_mem_cmp_exec,
	jit_mem_predicate_exec,
	jit_mem_concat_exec,
	jit_mem_to_port,
	jit_debug_print,
	jit_agg_max_exec,
	jit_agg_count_exec,
	jit_agg_sum_exec
};

#endif /* TARANTOOL_SQL_JIT_TYPES_H_INCLUDED */