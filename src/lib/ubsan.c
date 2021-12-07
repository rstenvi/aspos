#include "lib.h"
#include "log.h"

#ifdef UMODE
#define ubsan_exit(n) exit(n)
#else
#define ubsan_exit(n) kern_poweroff(1)
#endif

static int ubsan_panic_on_err = 1;

enum {
	type_kind_int = 0,
	type_kind_float = 1,
	type_unknown = 0xffff
};

struct type_descriptor {
	uint16_t type_kind;
	uint16_t type_info;
	char type_name[1];
};

struct source_location {
	const char *file_name;
	union {
		unsigned long reported;
		struct {
			uint32_t line;
			uint32_t column;
		};
	};
};

struct overflow_data {
	struct source_location location;
	struct type_descriptor *type;
};

struct type_mismatch_data {
	struct source_location location;
	struct type_descriptor *type;
	unsigned long alignment;
	unsigned char type_check_kind;
};

struct type_mismatch_data_v1 {
	struct source_location location;
	struct type_descriptor *type;
	unsigned char log_alignment;
	unsigned char type_check_kind;
};

struct type_mismatch_data_common {
	struct source_location *location;
	struct type_descriptor *type;
	unsigned long alignment;
	unsigned char type_check_kind;
};

struct nonnull_arg_data {
	struct source_location location;
	struct source_location attr_location;
	int arg_index;
};

struct vla_bound_data {
	struct source_location location;
	struct type_descriptor *type;
};

struct out_of_bounds_data {
	struct source_location location;
	struct type_descriptor *array_type;
	struct type_descriptor *index_type;
};

struct shift_out_of_bounds_data {
	struct source_location location;
	struct type_descriptor *lhs_type;
	struct type_descriptor *rhs_type;
};

struct unreachable_data {
	struct source_location location;
};

struct invalid_value_data {
	struct source_location location;
	struct type_descriptor *type;
};

enum UBSAN_OPS {
	UBSAN_PLUS = 0,
	UBSAN_SUB,
	UBSAN_DIV,
	UBSAN_REM,
	UBSAN_MUL,
	UBSAN_NEG
};

static const char* ubsan_msgs[] = {
	"value overflow (+)",
	"value overflow (-)",
	"value overflow (/)",
	"value overflow (P)",
	"value overflow (*)",
	"value overflow (~)",
};

static bool should_report(struct source_location* loc)	{
	return true;
}
static void ubsan_pr_post(void)	{
	bugprintf("UBSAN finished\n\n");
	if(ubsan_panic_on_err)	{
		ubsan_exit(1);
	}
}
static void ubsan_pr_loc(const char* msg, struct source_location* loc)	{
	bugprintf("BUG: UBSAN: %s | %s:%d:%d\n", msg, loc->file_name, loc->line, loc->column);
}
static void ubsan_pr_type(const char* msg, struct type_descriptor* desc)	{
	char* type;
	switch(desc->type_kind)	{
	case type_kind_int:
		type = "int";
		break;
	case type_kind_float:
		type = "float";
		break;
	default:
		type = "unknown";
		break;
	}
	bugprintf("UBSAN: %s | %s | %i name: %i\n", msg, type, desc->type_info, desc->type_name[0]);
}

static void handle_overflow(struct overflow_data *data, void *lhs, void *rhs, enum UBSAN_OPS op)	{
	struct source_location* loc = &(data->location);
	if(!should_report(loc))	return;

	ubsan_pr_loc(ubsan_msgs[op], loc);
	ubsan_pr_type("value", data->type);
	ubsan_pr_post();
}

void __ubsan_handle_add_overflow(void* data, void* lhs, void* rhs)	{
	handle_overflow((struct overflow_data*)data, lhs, rhs, UBSAN_PLUS);
}
void __ubsan_handle_sub_overflow(void* data, void* lhs, void* rhs)	{
	handle_overflow((struct overflow_data*)data, lhs, rhs, UBSAN_SUB);
}
void __ubsan_handle_mul_overflow(void* data, void* lhs, void* rhs)	{
	handle_overflow((struct overflow_data*)data, lhs, rhs, UBSAN_MUL);
}
void __ubsan_handle_negate_overflow(void* data, void* oldval)	{
	handle_overflow((struct overflow_data*)data, oldval, NULL, UBSAN_NEG);
}
void __ubsan_handle_divrem_overflow(void* data, void* lhs, void* rhs)	{
	handle_overflow((struct overflow_data*)data, lhs, rhs, UBSAN_REM);
}
/*void __ubsan_handle_type_mismatch(struct type_mismatch_data* data, void* ptr)	{

}*/
const char *type_mismatch_kinds[] = {
    "load of",
    "store to",
    "reference binding to",
    "member access within",
    "member call on",
    "constructor call on",
    "downcast of",
    "downcast of",
    "upcast of",
    "cast to virtual base of",
};
void __ubsan_handle_type_mismatch_v1(void* _data, void* ptr)	{
	struct type_mismatch_data_v1* data = (struct type_mismatch_data_v1*)_data;
	struct source_location* loc = &(data->location);
	if(!should_report(loc))	return;
	ubsan_pr_loc("type mismatch", loc);
	ubsan_pr_type("type", data->type);
	bugprintf("UBSAN: log_alignment: %i check_kind: %i\n", data->log_alignment, data->type_check_kind);
	bugprintf("kind: %s\n", type_mismatch_kinds[data->type_check_kind]);
	ubsan_pr_post();
}
void __ubsan_handle_out_of_bounds(void* _data, void* index)	{
	struct out_of_bounds_data* data = (struct out_of_bounds_data*)_data;
	struct source_location* loc = &(data->location);
	if(!should_report(loc))	return;
	ubsan_pr_loc("array out-of-bounds", loc);
	ubsan_pr_type("array type", data->array_type);
	ubsan_pr_type("index type", data->index_type);
	ubsan_pr_post();
}
void __ubsan_handle_shift_out_of_bounds(void* _data, void* lhs, void* rhs) {
	struct shift_out_of_bounds_data* data = (struct shift_out_of_bounds_data*)_data;
	struct source_location* loc = &(data->location);
	if(!should_report(loc))	return;
	ubsan_pr_loc("shift out-of-bounds", loc);
	ubsan_pr_type("lhs", data->lhs_type);
	ubsan_pr_type("rhs", data->rhs_type);
	ubsan_pr_post();
}
/*void __ubsan_handle_builtin_unreachable(struct unreachable_data* data) {
	while(1);
}*/
void __ubsan_handle_load_invalid_value(void* _data, void* val) {
	struct invalid_value_data* data = (struct invalid_value_data*)_data;
	struct source_location* loc = &(data->location);
	if(!should_report(loc))	return;
	ubsan_pr_loc("load invalid value", loc);
	ubsan_pr_type("type", data->type);
	bugprintf("UBSAN: val: %p\n", val);
	ubsan_pr_post();
}
void __ubsan_handle_vla_bound_not_positive(void* _data, void* bound) {
	struct vla_bound_data* data = (struct vla_bound_data*)_data;
	struct source_location* loc = &(data->location);
	if(!should_report(loc))	return;
	ubsan_pr_loc("VLA bound", loc);
	ubsan_pr_type("type", data->type);
	bugprintf("UBSAN: bound: %p\n", bound);
	ubsan_pr_post();
}
void __ubsan_handle_nonnull_arg(void* _data)	{
	struct nonnull_arg_data* data = (struct nonnull_arg_data*)_data;
	struct source_location* loc = &(data->location);
	struct source_location* attr_loc = &(data->attr_location);
	if(!should_report(loc))	return;
	ubsan_pr_loc("nonnull arg", loc);
	ubsan_pr_loc("nonnull arg", attr_loc);
	bugprintf("UBSAN: arg index %i\n", data->arg_index);
	ubsan_pr_post();
}

void __ubsan_handle_pointer_overflow(void* _loc, void* base, void* result)	{
	struct source_location* loc = (struct source_location*)_loc;
	if(!should_report(loc))	return;
	ubsan_pr_loc("ptr overflow", loc);
//	bugprintf("UBSAN: pointer overflow %p %p %p\n", data, base, result);
	ubsan_pr_post();
}
