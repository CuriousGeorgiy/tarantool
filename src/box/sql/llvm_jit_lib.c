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

/**
 * This source file never gets linked, we only generate the LLVM bootstrap
 * module, required for JIT compilation, from it.
 */

#include "sqlInt.h"
#include "vdbeInt.h"
#include "vdbe.h"
#include "mem.h"

#include "box/sql.h"
#include "box/tuple.h"
#include "box/tuple_format.h"

#include "math.h"

#if defined(SQL_TEST)
#define UPDATE_MAX_BLOBSIZE(P)  updateMaxBlobsize(P)
#else
#define UPDATE_MAX_BLOBSIZE(P)
#endif

__attribute__((always_inline)) int
mem_from_mp_ephemeral(struct Mem *mem, const char *buf, uint32_t *len)
{
	const char *start_buf = buf;
	switch (mp_typeof(*buf)) {
	case MP_ARRAY: {
		mem->z = (char *)buf;
		mp_next(&buf);
		mem->n = buf - mem->z;
		mem->type = MEM_TYPE_ARRAY;
		mem->flags = MEM_Ephem;
		mem->field_type = FIELD_TYPE_ARRAY;
		break;
	}
	case MP_MAP: {
		mem->z = (char *)buf;
		mp_next(&buf);
		mem->n = buf - mem->z;
		mem->type = MEM_TYPE_MAP;
		mem->flags = MEM_Ephem;
		mem->field_type = FIELD_TYPE_MAP;
		break;
	}
	case MP_EXT: {
		mem->z = (char *)buf;
		mp_next(&buf);
		mem->n = buf - mem->z;
		mem->type = MEM_TYPE_BIN;
		mem->flags = MEM_Ephem;
		mem->field_type = FIELD_TYPE_VARBINARY;
		break;
	}
	case MP_NIL: {
		mp_decode_nil(&buf);
		mem->type = MEM_TYPE_NULL;
		mem->flags = 0;
		mem->field_type = field_type_MAX;
		break;
	}
	case MP_BOOL: {
		mem->u.b = mp_decode_bool(&buf);
		mem->type = MEM_TYPE_BOOL;
		mem->flags = 0;
		mem->field_type = FIELD_TYPE_BOOLEAN;
		break;
	}
	case MP_UINT: {
		uint64_t v = mp_decode_uint(&buf);
		mem->u.u = v;
		mem->type = MEM_TYPE_UINT;
		mem->flags = 0;
		mem->field_type = FIELD_TYPE_INTEGER;
		break;
	}
	case MP_INT: {
		mem->u.i = mp_decode_int(&buf);
		mem->type = MEM_TYPE_INT;
		mem->flags = 0;
		mem->field_type = FIELD_TYPE_INTEGER;
		break;
	}
	case MP_STR: {
		/* XXX u32->int */
		mem->n = (int) mp_decode_strl(&buf);
		mem->type = MEM_TYPE_STR;
		mem->flags = MEM_Ephem;
		mem->field_type = FIELD_TYPE_STRING;
install_blob:
		mem->z = (char *)buf;
		buf += mem->n;
		break;
	}
	case MP_BIN: {
		/* XXX u32->int */
		mem->n = (int) mp_decode_binl(&buf);
		mem->type = MEM_TYPE_BIN;
		mem->flags = MEM_Ephem;
		mem->field_type = FIELD_TYPE_VARBINARY;
		goto install_blob;
	}
	case MP_FLOAT: {
		mem->u.r = mp_decode_float(&buf);
		if (sqlIsNaN(mem->u.r)) {
			mem->type = MEM_TYPE_NULL;
			mem->flags = 0;
			mem->field_type = FIELD_TYPE_DOUBLE;
		} else {
			mem->type = MEM_TYPE_DOUBLE;
			mem->flags = 0;
			mem->field_type = FIELD_TYPE_DOUBLE;
		}
		break;
	}
	case MP_DOUBLE: {
		mem->u.r = mp_decode_double(&buf);
		if (sqlIsNaN(mem->u.r)) {
			mem->type = MEM_TYPE_NULL;
			mem->flags = 0;
			mem->field_type = FIELD_TYPE_DOUBLE;
		} else {
			mem->type = MEM_TYPE_DOUBLE;
			mem->flags = 0;
			mem->field_type = FIELD_TYPE_DOUBLE;
		}
		break;
	}
	default:
		unreachable();
	}
	*len = (uint32_t)(buf - start_buf);
	return 0;
}

__attribute__((always_inline)) void
mem_clear(struct Mem *mem)
{
	if ((mem->type & (MEM_TYPE_AGG | MEM_TYPE_FRAME)) != 0 ||
	    (mem->flags & MEM_Dyn) != 0) {
		if (mem->type == MEM_TYPE_AGG)
			sql_vdbemem_finalize(mem, mem->u.func);
		assert(mem->type != MEM_TYPE_AGG);
		if ((mem->flags & MEM_Dyn) != 0) {
			assert(mem->xDel != SQL_DYNAMIC && mem->xDel != NULL);
			mem->xDel((void *)mem->z);
		} else if (mem->type == MEM_TYPE_FRAME) {
			struct VdbeFrame *frame = mem->u.pFrame;
			frame->pParent = frame->v->pDelFrame;
			frame->v->pDelFrame = frame;
		}
	}
	mem->type = MEM_TYPE_NULL;
	mem->flags = 0;
	mem->field_type = field_type_MAX;
}

__attribute__((always_inline)) static int
sqlVdbeMemGrow(struct Mem *pMem, int n, int bPreserve)
{
	assert(sqlVdbeCheckMemInvariants(pMem));
	testcase(pMem->db == 0);

	/* If the bPreserve flag is set to true, then the memory cell must already
	 * contain a valid string or blob value.
	 */
	assert(bPreserve == 0 || mem_is_bytes(pMem));
	testcase(bPreserve && pMem->z == 0);

	assert(pMem->szMalloc == 0 ||
	       pMem->szMalloc == sqlDbMallocSize(pMem->db, pMem->zMalloc));
	if (pMem->szMalloc < n) {
		if (n < 32)
			n = 32;
		if (bPreserve && pMem->szMalloc > 0 && pMem->z == pMem->zMalloc) {
			pMem->z = pMem->zMalloc =
			sqlDbReallocOrFree(pMem->db, pMem->z, n);
			bPreserve = 0;
		} else {
			if (pMem->szMalloc > 0)
				sqlDbFree(pMem->db, pMem->zMalloc);
			pMem->zMalloc = sqlDbMallocRaw(pMem->db, n);
		}
		if (pMem->zMalloc == 0) {
			mem_clear(pMem);
			pMem->z = 0;
			pMem->szMalloc = 0;
			return -1;
		} else {
			pMem->szMalloc = sqlDbMallocSize(pMem->db,
							 pMem->zMalloc);
		}
	}

	if (bPreserve && pMem->z && pMem->z != pMem->zMalloc) {
		memcpy(pMem->zMalloc, pMem->z, pMem->n);
	}
	if ((pMem->flags & MEM_Dyn) != 0) {
		assert(pMem->xDel != 0 && pMem->xDel != SQL_DYNAMIC);
		pMem->xDel((void *)(pMem->z));
	}

	pMem->z = pMem->zMalloc;
	pMem->flags &= ~(MEM_Dyn | MEM_Ephem | MEM_Static);
	return 0;
}

__attribute__((always_inline)) int
mem_from_mp(struct Mem *mem, const char *buf, uint32_t *len)
{
	if (mem_from_mp_ephemeral(mem, buf, len) != 0)
		return -1;
	if (mem_is_bytes(mem)) {
		assert((mem->flags & MEM_Ephem) != 0);
		if (sqlVdbeMemGrow(mem, mem->n, 1) != 0)
			return -1;
	}
	return 0;
}

__attribute__((always_inline)) uint32_t
vdbe_field_ref_closest_slotno(struct vdbe_field_ref *field_ref,
			      uint32_t fieldno)
{
	uint64_t slot_bitmask = field_ref->slot_bitmask;
	assert(slot_bitmask != 0 && fieldno > 0);
	uint64_t le_mask = fieldno < 64 ? slot_bitmask & ((1LLU << fieldno) - 1)
					: slot_bitmask;
	assert(bit_clz_u64(le_mask) < 64);
	return 64 - bit_clz_u64(le_mask) - 1;
}

__attribute__((always_inline)) const struct tuple_field *
vdbe_field_ref_fetch_field(struct vdbe_field_ref *field_ref, uint32_t fieldno)
{
	if (field_ref->tuple == NULL)
		return NULL;
	struct tuple_format *format = tuple_format(field_ref->tuple);
	if (fieldno >= tuple_format_field_count(format))
		return NULL;
	return tuple_format_field(format, fieldno);
}

__attribute__((always_inline)) const char *
vdbe_field_ref_fetch_data(struct vdbe_field_ref *field_ref, uint32_t fieldno)
{
	if (field_ref->slots[fieldno] != 0)
		return field_ref->data + field_ref->slots[fieldno];

	const char *field_begin;
	const struct tuple_field *field = vdbe_field_ref_fetch_field(field_ref,
								     fieldno);
	if (field != NULL && field->offset_slot != TUPLE_OFFSET_SLOT_NIL) {
		field_begin = tuple_field(field_ref->tuple, fieldno);
	} else {
		uint32_t prev = vdbe_field_ref_closest_slotno(field_ref,
							      fieldno);;
		if (fieldno >= 64) {
			/*
			 * There could be initialized slots
			 * that didn't fit in the bitmask.
			 * Try to find the biggest initialized
			 * slot.
			 */
			for (uint32_t it = fieldno - 1; it > prev; it--) {
				if (field_ref->slots[it] == 0)
					continue;
				prev = it;
				break;
			}
		}
		field_begin = field_ref->data + field_ref->slots[prev];
		for (prev++; prev < fieldno; prev++) {
			mp_next(&field_begin);
			field_ref->slots[prev] =
			(uint32_t)(field_begin - field_ref->data);
			bitmask64_set_bit(&field_ref->slot_bitmask, prev);
		}
		mp_next(&field_begin);
	}
	field_ref->slots[fieldno] = (uint32_t)(field_begin - field_ref->data);
	bitmask64_set_bit(&field_ref->slot_bitmask, fieldno);
	return field_begin;
}

__attribute__((always_inline)) int
vdbe_field_ref_fetch(struct vdbe_field_ref *field_ref, uint32_t fieldno,
		     struct Mem *dest_mem)
{
	if (fieldno >= field_ref->field_count) {
		UPDATE_MAX_BLOBSIZE(dest_mem);
		return 0;
	}
	assert(sqlVdbeCheckMemInvariants(dest_mem) != 0);
	const char *data = vdbe_field_ref_fetch_data(field_ref, fieldno);
	uint32_t dummy;
	if (mem_from_mp(dest_mem, data, &dummy) != 0)
		return -1;
	UPDATE_MAX_BLOBSIZE(dest_mem);
	return 0;
}

__attribute__((always_inline)) void
vdbe_field_ref_create(struct vdbe_field_ref *field_ref, struct tuple *tuple,
		      const char *data, uint32_t data_sz)
{
	field_ref->tuple = tuple;
	field_ref->data = data;
	field_ref->data_sz = data_sz;

	const char *field0 = data;
	field_ref->field_count = mp_decode_array((const char **) &field0);
	field_ref->slots[0] = (uint32_t)(field0 - data);
	memset(&field_ref->slots[1], 0,
	       field_ref->field_count * sizeof(field_ref->slots[0]));
	field_ref->slot_bitmask = 0;
	bitmask64_set_bit(&field_ref->slot_bitmask, 0);
}

__attribute__((always_inline)) void
vdbe_field_ref_prepare_tuple(struct vdbe_field_ref *field_ref,
			     struct tuple *tuple)
{
	vdbe_field_ref_create(field_ref, tuple, tuple_data(tuple),
			      tuple->bsize);
}

#ifndef NDEBUG
__attribute__((always_inline)) int
sqlCursorIsValid(BtCursor *pCur)
{
	return pCur && pCur->eState == CURSOR_VALID;
}
#endif

__attribute__((always_inline)) int
vdbe_op_col(Vdbe *vdbe, int csr, int col, struct Mem *tgt, int tgt_idx)
{
	assert(vdbe != NULL);
	assert(csr >= 0 && csr < vdbe->nCursor);
	assert(col >= 0);
	assert(tgt != NULL);
	assert(tgt_idx >0 && tgt_idx <= (vdbe->nMem + 1 - vdbe->nCursor));
	say_info("tgt[%p]", tgt);
	VdbeCursor *vdbe_csr; /* The VDBE cursor. */
	BtCursor *btree_csr; /* The BTree cursor. */
	Mem *pReg; /* PseudoTable input register. */
	vdbe_csr = vdbe->apCsr[csr];
	assert(vdbe_csr != NULL);
	assert(col < vdbe_csr->nField);
	assert(vdbe_csr->eCurType != CURTYPE_PSEUDO || vdbe_csr->nullRow);
	assert(vdbe_csr->eCurType != CURTYPE_SORTER);
	if (vdbe_csr->cacheStatus != vdbe->cacheCtr) {
		if (vdbe_csr->nullRow) {
			if (vdbe_csr->eCurType == CURTYPE_PSEUDO) {
				assert(vdbe_csr->uc.pseudoTableReg > 0);
				pReg = &vdbe->aMem[vdbe_csr->uc.pseudoTableReg];
				assert(mem_is_bin(pReg));
				assert(memIsValid(pReg));
				vdbe_field_ref_prepare_data(&vdbe_csr->field_ref,
							    pReg->z, pReg->n);
			} else {
				return 0;
			}
		} else {
			btree_csr = vdbe_csr->uc.pCursor;
			assert(vdbe_csr->eCurType == CURTYPE_TARANTOOL);
			assert(btree_csr);
			assert(sqlCursorIsValid(btree_csr));
			assert(btree_csr->curFlags & BTCF_TaCursor ||
			       btree_csr->curFlags & BTCF_TEphemCursor);
			vdbe_field_ref_prepare_tuple(&vdbe_csr->field_ref,
						     btree_csr->last_tuple);
		}
		vdbe_csr->cacheStatus = vdbe->cacheCtr;
	}
	enum field_type field_type = field_type_MAX;
	if (vdbe_csr->eCurType == CURTYPE_TARANTOOL)
		field_type = vdbe_csr->uc.pCursor->space->def->fields[col].type;
	else if (vdbe_csr->eCurType == CURTYPE_SORTER)
		field_type = vdbe_sorter_get_field_type(vdbe_csr->uc.pSorter, col);
	if (vdbe_field_ref_fetch(&vdbe_csr->field_ref, col, tgt) != 0)
		return -1;
	tgt->field_type = field_type;
	return 0;
}

__attribute__((always_inline)) static void *
sql_sized_realloc(void *pPrior, int nByte)
{
	sql_int64 *p = (sql_int64 *) pPrior;
	assert(pPrior != 0 && nByte > 0);
	assert(nByte == ROUND8(nByte));	/* EV: R-46199-30249 */
	p--;
	p = realloc(p, nByte + 8);
	if (p == NULL) {
		sql_get()->mallocFailed = 1;
		diag_set(OutOfMemory, nByte, "realloc", "p");
		return NULL;
	}
	p[0] = nByte;
	p++;
	return (void *)p;
}

__attribute__((always_inline)) void *
sqlRealloc(void *pOld, u64 nBytes)
{
	int nOld, nNew;
	void *pNew;
	if (pOld == 0) {
		return sqlMalloc(nBytes);	/* IMP: R-04300-56712 */
	}
	if (nBytes == 0) {
		sql_free(pOld);	/* IMP: R-26507-47431 */
		return 0;
	}
	if (nBytes >= 0x7fffff00) {
		/* The 0x7ffff00 limit term is explained in comments on sqlMalloc() */
		return 0;
	}
	nOld = sqlMallocSize(pOld);
	nNew = ROUND8((int)nBytes);
	if (nOld == nNew)
		pNew = pOld;
	else
		pNew = sql_sized_realloc(pOld, nNew);
	assert(EIGHT_BYTE_ALIGNMENT(pNew));	/* IMP: R-11148-40995 */
	return pNew;
}

__attribute__((always_inline)) void *
sql_realloc64(void *pOld, sql_uint64 n)
{
	return sqlRealloc(pOld, n);
}

__attribute__((always_inline)) void *
sqlDbMallocRaw(sql * db, u64 n)
{
	void *p;
	if (db)
		return sqlDbMallocRawNN(db, n);
	p = sqlMalloc(n);
	return p;
}

__attribute__((always_inline)) static void *
sql_sized_malloc(int nByte)
{
	sql_int64 *p;
	assert(nByte > 0);
	nByte = ROUND8(nByte);
	p = malloc(nByte + 8);
	if (p == NULL) {
		sql_get()->mallocFailed = 1;
		diag_set(OutOfMemory, nByte, "malloc", "p");
		return NULL;
	}
	p[0] = nByte;
	p++;
	return (void *)p;
}

__attribute__((always_inline)) static int
sql_sized_sizeof(void *pPrior)
{
	sql_int64 *p;
	assert(pPrior != 0);
	p = (sql_int64 *) pPrior;
	p--;
	return (int)p[0];
}

__attribute__((always_inline)) int
sqlMallocSize(void *p)
{
	return sql_sized_sizeof(p);
}

__attribute__((always_inline)) void *
sqlMalloc(u64 n)
{
	void *p;
	if (n == 0 || n >= 0x7fffff00) {
		p = 0;
	} else {
		p = sql_sized_malloc((int)n);
	}
	assert(EIGHT_BYTE_ALIGNMENT(p));
	return p;
}

__attribute__((always_inline)) static void *
dbMallocRawFinish(sql * db, u64 n)
{
	void *p;
	assert(db != 0);
	p = sqlMalloc(n);
	if (!p)
		sqlOomFault(db);
	return p;
}

__attribute__((always_inline)) void *
sqlDbMallocRawNN(sql * db, u64 n)
{
	assert(db != NULL);
	LookasideSlot *pBuf;
	if (db->lookaside.bDisable == 0) {
		assert(db->mallocFailed == 0);
		if (n > db->lookaside.sz) {
			db->lookaside.anStat[1]++;
		} else if ((pBuf = db->lookaside.pFree) == 0) {
			db->lookaside.anStat[2]++;
		} else {
			db->lookaside.pFree = pBuf->pNext;
			db->lookaside.nOut++;
			db->lookaside.anStat[0]++;
			if (db->lookaside.nOut > db->lookaside.mxOut) {
				db->lookaside.mxOut = db->lookaside.nOut;
			}
			return (void *)pBuf;
		}
	} else if (db->mallocFailed) {
		return 0;
	}
	return dbMallocRawFinish(db, n);
}

__attribute__((always_inline)) void
sql_free(void *p)
{
	if (p == NULL)
		return;
	sql_int64 *raw_p = (sql_int64 *) p;
	raw_p--;
	free(raw_p);
}

__attribute__((always_inline)) static int
isLookaside(sql * db, void *p)
{
	return SQL_WITHIN(p, db->lookaside.pStart, db->lookaside.pEnd);
}

__attribute__((always_inline)) void
sqlDbFree(sql * db, void *p)
{
	if (db != NULL) {
		if (isLookaside(db, p)) {
			LookasideSlot *pBuf = (LookasideSlot *) p;
			pBuf->pNext = db->lookaside.pFree;
			db->lookaside.pFree = pBuf;
			db->lookaside.nOut--;
			return;
		}
	}
	sql_free(p);
}

__attribute__((always_inline)) static void *
dbReallocFinish(sql * db, void *p, u64 n)
{
	void *pNew = 0;
	assert(db != 0);
	assert(p != 0);
	if (db->mallocFailed == 0) {
		if (isLookaside(db, p)) {
			pNew = sqlDbMallocRawNN(db, n);
			if (pNew) {
				memcpy(pNew, p, db->lookaside.sz);
				sqlDbFree(db, p);
			}
		} else {
			pNew = sql_realloc64(p, n);
			if (!pNew)
				sqlOomFault(db);
		}
	}
	return pNew;
}

__attribute__((always_inline)) void *
sqlDbRealloc(sql * db, void *p, u64 n)
{
	assert(db != 0);
	if (p == 0)
		return sqlDbMallocRawNN(db, n);
	if (isLookaside(db, p) && n <= db->lookaside.sz)
		return p;
	return dbReallocFinish(db, p, n);
}

__attribute__((always_inline)) void *
sqlDbReallocOrFree(sql * db, void *p, u64 n)
{
	void *pNew;
	pNew = sqlDbRealloc(db, p, n);
	if (!pNew) {
		sqlDbFree(db, p);
	}
	return pNew;
}

__attribute__((always_inline)) int
sqlDbMallocSize(sql * db, void *p)
{
	assert(p != 0);
	if (db == 0 || !isLookaside(db, p))
		return sql_sized_sizeof(p);
	else
		return db->lookaside.sz;
}

__attribute__((always_inline)) int
sqlVdbeCheckMemInvariants(Mem * p)
{
	/* If MEM_Dyn is set then Mem.xDel!=0.
	 * Mem.xDel is might not be initialized if MEM_Dyn is clear.
	 */
	assert((p->flags & MEM_Dyn) == 0 || p->xDel != 0);

	/* MEM_Dyn may only be set if Mem.szMalloc==0.  In this way we
	 * ensure that if Mem.szMalloc>0 then it is safe to do
	 * Mem.z = Mem.zMalloc without having to check Mem.flags&MEM_Dyn.
	 * That saves a few cycles in inner loops.
	 */
	assert((p->flags & MEM_Dyn) == 0 || p->szMalloc == 0);

	/* The szMalloc field holds the correct memory allocation size */
	assert(p->szMalloc == 0 ||
	       p->szMalloc == sqlDbMallocSize(p->db, p->zMalloc));

	/* If p holds a string or blob, the Mem.z must point to exactly
	 * one of the following:
	 *
	 *   (1) Memory in Mem.zMalloc and managed by the Mem object
	 *   (2) Memory to be freed using Mem.xDel
	 *   (3) An ephemeral string or blob
	 *   (4) A static string or blob
	 */
	if ((p->type & (MEM_TYPE_STR | MEM_TYPE_BIN)) != 0 && p->n > 0) {
		assert(((p->szMalloc > 0 && p->z == p->zMalloc) ? 1 : 0) +
		       ((p->flags & MEM_Dyn) != 0 ? 1 : 0) +
		       ((p->flags & MEM_Ephem) != 0 ? 1 : 0) +
		       ((p->flags & MEM_Static) != 0 ? 1 : 0) == 1);
	}
	return 1;
}

__attribute__((always_inline)) int
sql_vdbemem_finalize(struct Mem *mem, struct func *func)
{
	assert(func != NULL);
	assert(func->def->language == FUNC_LANGUAGE_SQL_BUILTIN);
	assert(func->def->aggregate == FUNC_AGGREGATE_GROUP);
	assert(mem->type == MEM_TYPE_NULL || func == mem->u.func);
	sql_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	Mem t;
	memset(&t, 0, sizeof(t));
	t.type = MEM_TYPE_NULL;
	assert(t.flags == 0);
	t.db = mem->db;
	t.field_type = field_type_MAX;
	ctx.pOut = &t;
	ctx.pMem = mem;
	ctx.func = func;
	((struct func_sql_builtin *)func)->finalize(&ctx);
	assert((mem->flags & MEM_Dyn) == 0);
	if (mem->szMalloc > 0)
		sqlDbFree(mem->db, mem->zMalloc);
	memcpy(mem, &t, sizeof(t));
	return ctx.is_aborted ? -1 : 0;
}

__attribute__((always_inline)) int
sqlVdbeMemExpandBlob(struct Mem * pMem)
{
	int nByte;
	assert(pMem->flags & MEM_Zero);
	assert(pMem->type == MEM_TYPE_BIN);

	nByte = pMem->n + pMem->u.nZero;
	if (nByte <= 0) {
		nByte = 1;
	}
	if (sqlVdbeMemGrow(pMem, nByte, 1)) {
		return -1;
	}

	memset(&pMem->z[pMem->n], 0, pMem->u.nZero);
	pMem->n += pMem->u.nZero;
	pMem->flags &= ~(MEM_Zero | MEM_Term);
	return 0;
}

__attribute__((always_inline)) int
mem_copy(struct Mem *to, const struct Mem *from)
{
	mem_clear(to);
	to->u = from->u;
	to->type = from->type;
	to->flags = from->flags;
	to->field_type = from->field_type;
	to->n = from->n;
	to->z = from->z;
	if (!mem_is_bytes(to))
		return 0;
	if ((to->flags & MEM_Static) != 0)
		return 0;
	assert((to->flags & MEM_Zero) == 0 || to->type == MEM_TYPE_BIN);
	if ((to->flags & MEM_Zero) != 0)
		return sqlVdbeMemExpandBlob(to);
	to->zMalloc = sqlDbReallocOrFree(to->db, to->zMalloc, to->n);
	if (to->zMalloc == NULL)
		return -1;
	to->szMalloc = sqlDbMallocSize(to->db, to->zMalloc);
	memcpy(to->zMalloc, to->z, to->n);
	to->z = to->zMalloc;
	to->flags &= MEM_Term;
	return 0;
}

__attribute__((always_inline)) void
mem_set_null(struct Mem *mem)
{
	mem_clear(mem);
}

__attribute__((always_inline)) void
mem_set_int(struct Mem *mem, int64_t value, bool is_neg)
{
	mem_clear(mem);
	mem->u.i = value;
	mem->type = is_neg ? MEM_TYPE_INT : MEM_TYPE_UINT;
	assert(mem->flags == 0);
	mem->field_type = FIELD_TYPE_INTEGER;
}

__attribute__((always_inline)) void
mem_set_bool(struct Mem *mem, bool value)
{
	mem_clear(mem);
	mem->u.b = value;
	mem->type = MEM_TYPE_BOOL;
	assert(mem->flags == 0);
	mem->field_type = FIELD_TYPE_BOOLEAN;
}

__attribute__((always_inline)) int
sqlIsNaN(double x)
{
	int rc;
	rc = isnan(x);
	return rc;
}

__attribute__((always_inline)) void
mem_set_double(struct Mem *mem, double value)
{
	mem_clear(mem);
	mem->field_type = FIELD_TYPE_DOUBLE;
	assert(mem->flags == 0);
	if (sqlIsNaN(value))
		return;
	mem->u.r = value;
	mem->type = MEM_TYPE_DOUBLE;
}

__attribute__((always_inline)) static void
set_str_const(struct Mem *mem, char *value, uint32_t len, int alloc_type)
{
	assert((alloc_type & (MEM_Static | MEM_Ephem)) != 0);
	mem_clear(mem);
	mem->z = value;
	mem->n = len;
	mem->type = MEM_TYPE_STR;
	mem->flags = alloc_type;
	mem->field_type = FIELD_TYPE_STRING;
}

__attribute__((always_inline)) void
mem_set_str0_static(struct Mem *mem, char *value)
{
	set_str_const(mem, value, strlen(value), MEM_Static);
	mem->flags |= MEM_Term;
}