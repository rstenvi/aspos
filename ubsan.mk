
# float-cast-overflow, pointer-overflow
UBSAN_SAN = undefined
#UBSAN_SAN = alignment,bool,builtin,bounds,enum,integer-divide-by-zero,nonnull-attribute,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound
CFLAGS += -fsanitize=$(UBSAN_SAN)

