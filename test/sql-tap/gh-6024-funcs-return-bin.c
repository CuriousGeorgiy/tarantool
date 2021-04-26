#include "msgpuck.h"
#include "module.h"
#include "uuid/mp_uuid.h"
#include "mp_decimal.h"

enum {
	BUF_SIZE = 512,
};

int
ret_bin(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
	(void)args;
	(void)args_end;
	const char bin[] = "some varbinary string";
	char tuple_buf[BUF_SIZE];
	assert(mp_sizeof_array(1) + mp_sizeof_bin(sizeof(bin)) < BUF_SIZE);
	char *d = tuple_buf;
	d = mp_encode_array(d, 1);
	d = mp_encode_bin(d, bin, sizeof(bin));

	box_tuple_format_t *fmt = box_tuple_format_default();
	box_tuple_t *tuple = box_tuple_new(fmt, tuple_buf, d);
	if (tuple == NULL)
		return -1;
	return box_return_tuple(ctx, tuple);
}

int
ret_uuid(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
	(void)args;
	(void)args_end;
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

int
ret_decimal(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
	(void)args;
	(void)args_end;
	decimal_t dec;
	decimal_from_string(&dec, "9999999999999999999.9999999999999999999");
	char tuple_buf[BUF_SIZE];
	assert(mp_sizeof_array(1) + mp_sizeof_decimal(&dec) < BUF_SIZE);
	char *d = tuple_buf;
	d = mp_encode_array(d, 1);
	d = mp_encode_decimal(d, &dec);

	box_tuple_format_t *fmt = box_tuple_format_default();
	box_tuple_t *tuple = box_tuple_new(fmt, tuple_buf, d);
	if (tuple == NULL)
		return -1;
	return box_return_tuple(ctx, tuple);
}
