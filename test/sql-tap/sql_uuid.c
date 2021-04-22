#include "msgpuck.h"
#include "module.h"
#include "uuid/mp_uuid.h"
#include "mp_extension_types.h"

enum {
	BUF_SIZE = 512,
};

int
is_uuid(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
	uint32_t arg_count = mp_decode_array(&args);
	if (arg_count != 1) {
		return box_error_set(__FILE__, __LINE__, ER_PROC_C,
				     "invalid argument count");
	}
	bool is_uuid;
	if (mp_typeof(*args) == MP_EXT) {
		const char *str = args;
		int8_t type;
		mp_decode_extl(&str, &type);
		is_uuid = type == MP_UUID;
	} else {
		is_uuid = false;
	}

	char tuple_buf[BUF_SIZE];
	assert(mp_sizeof_array(1) + mp_sizeof_bool(is_uuid) < BUF_SIZE);
	char *d = tuple_buf;
	d = mp_encode_array(d, 1);
	d = mp_encode_bool(d, is_uuid);

	box_tuple_format_t *fmt = box_tuple_format_default();
	box_tuple_t *tuple = box_tuple_new(fmt, tuple_buf, d);
	if (tuple == NULL)
		return -1;
	return box_return_tuple(ctx, tuple);
}

int
ret_uuid(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
	struct tt_uuid uuid;
	memset(&uuid, 0x11, sizeof(uuid));
	char tuple_buf[BUF_SIZE];
	assert(mp_sizeof_array(1) + mp_sizeof_uuid() < BUF_SIZE);
	char *d = tuple_buf;
	d = mp_encode_array(d, 1);
	d = mp_encode_uuid(d, &uuid);

	box_tuple_format_t *fmt = box_tuple_format_default();
	box_tuple_t *tuple = box_tuple_new(fmt, tuple_buf, d);
	if (tuple == NULL)
		return -1;
	return box_return_tuple(ctx, tuple);
}
