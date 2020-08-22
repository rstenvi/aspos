#include "kernel.h"


#define OF_DT_HEADER 0xd00dfeed

#define OF_DT_BEGIN_NODE  0x00000001
#define OF_DT_PROP        0x00000003
#define OF_DT_END_NODE    0x00000002
#define OF_DT_END         0x00000009


struct dtbreg {
	uint64_t addr, len;
};


struct dtb_header {
	uint32_t magic;
	uint32_t totalsize;
	uint32_t off_dt_struct;
	uint32_t off_dt_strings;
	uint32_t off_mem_rsvmap;
	uint32_t version;
	uint32_t last_comp_version;
	uint32_t boot_cpuid_phys;
	uint32_t size_dt_strings;
	uint32_t size_dt_struct;
};

uint32_t dtb_translate_ref(void* ref)	{
	return be_u32_to_cpu(ref);
}

int dtb_get_reg(void* reg, uint32_t cellssz, uint32_t cellsaddr, uint64_t* outaddr, uint64_t* outlen)	{
	uint64_t addr = 0, length = 0;
	ASSERT_TRUE(cellssz == 2 && cellsaddr == 2, "Unsupported sizes");

	uint32_t tmp = dtb_translate_ref(reg);
	addr = (uint64_t)(tmp) << 32;
	tmp = dtb_translate_ref(reg + 4);
	addr += tmp;

	tmp = dtb_translate_ref(reg + 8);
	length = (uint64_t)(tmp) << 32;
	tmp = dtb_translate_ref(reg + 12);
	length += tmp;

	*outaddr = addr;
	*outlen = length;
	return 0;
}

void* dtb_get_ref(const char* node, const char* prop, int skip, int* cells_sz, int* cells_addr)	{
	void* dtb = cpu_get_dtb();
	struct dtb_header* header = (struct dtb_header*)dtb;
	uint32_t offset, lastoff, tmp;
	void* current;
	char* nodename;
	char* strings = NULL;
	bool correctnode = false;
	void* ret = NULL;
	int nlen = strlen(node);

	// Sanity check to ensure we have correct pointer
	if(be_u32bits_to_cpu(header->magic) != OF_DT_HEADER)	{
		while(1);
		return 0;
	}

	offset = be_u32bits_to_cpu(header->off_dt_struct);
	lastoff = be_u32bits_to_cpu(header->size_dt_struct) + offset;

	strings = (char*)(dtb + be_u32bits_to_cpu(header->off_dt_strings));

	// Default values
	if(cells_sz != NULL)	*cells_sz = 2;
	if(cells_addr != NULL)	*cells_addr = 1;

	while(offset < lastoff)	{
		correctnode = false;
		current = (dtb + offset);
		tmp = be_u32_to_cpu(current);
		if(tmp == OF_DT_BEGIN_NODE)	{
			// Start of new node
		}
		else if(tmp == OF_DT_END_NODE)	{
			// Node has finished
			offset += 4;
			continue;
		}
		else if(tmp == OF_DT_END)	{
			// Finished with parsing
			break;
		}

		// We have started a new node
		nodename = (char*)((ptr_t)current + 4);

		tmp = strlen(nodename) + 1;
		ALIGN_UP_POW2(tmp, 4)
		

		// Special handling to make it easier to search
		if(nodename[0] == 0x00)	{
			nodename = "root";
		}


		if(strncmp(nodename, node, nlen) == 0)	{
			if(skip == 0)	{
				correctnode = true;
			}
			else	{
				skip--;
			}
		}

		// Add begin node marker + nodestring
		offset += 4 + tmp;
		current = (dtb + offset);

		tmp = be_u32_to_cpu(current);
		while(tmp == OF_DT_PROP)	{
			uint32_t propsz = be_u32_to_cpu(current + 4);
			uint32_t propoff = be_u32_to_cpu(current + 8);
			char* propname = (char*)(strings + propoff);

			if(cells_sz != NULL && strcmp(propname, "#size-cells") == 0)	{
				*cells_sz = be_u32_to_cpu(current + 12);
			}
			if(cells_addr != NULL && strcmp(propname, "#address-cells") == 0)	{
				*cells_addr = be_u32_to_cpu(current + 12);
			}

			if(correctnode && strcmp(propname, prop) == 0)	{
				// We have found the property the caller is looking for
				ret = (current + 12);
				return ret;

			}
			// Move to next prop
			if(propsz > 0)	{ ALIGN_UP_POW2(propsz, 4); }
			offset += 12 + propsz;
			current = (dtb + offset);
			tmp = be_u32_to_cpu(current);
		}

	}
	return ret;
}



// This code is after the init phase


int dtb_num_props(void* start)	{
	uint32_t tmp, offset = 0, propsz;
	int count = 0;

	while(be_u32_to_cpu(start + offset) == OF_DT_PROP)	{
		propsz = be_u32_to_cpu(start + offset + 4);
		if(propsz > 0)	{ ALIGN_UP_POW2(propsz, 4); }
		offset += 12 + propsz;
		count++;
	}
	return count;
}

struct dtb_node* dtb_parse_node(void* start, char* strings, uint32_t* foffset)	{
	uint32_t tmp, offset, propsz, propoff;
	int pcount = 0;
	struct dtb_node* ret = (struct dtb_node*)malloc( sizeof(struct dtb_node) );
	if(ret == NULL)	return ret;

	ret->name = (char*)(start + cpu_linear_offset());
	ret->childs = NULL;


	offset = strlen(ret->name) + 1;
	ALIGN_UP_POW2(offset, 4);

	// Get number of properties so we can allocate array
	ret->numprops = dtb_num_props(start + offset);
	ret->props = (struct dtb_property*)malloc( sizeof(struct dtb_property) * ret->numprops );

	while(be_u32_to_cpu(start + offset) == OF_DT_PROP)	{
		
		propsz = be_u32_to_cpu(start + offset + 4);
		propoff = be_u32_to_cpu(start + offset + 8);

		ret->props[pcount].name = (strings + propoff + cpu_linear_offset());
		ret->props[pcount].valsize = propsz;
		ret->props[pcount].data = (start + offset + 12 + cpu_linear_offset());
		ret->props[pcount].type = UNKNOWN;


		propsz = be_u32_to_cpu(start + offset + 4);
		if(propsz > 0)	{ ALIGN_UP_POW2(propsz, 4); }
		offset += 12 + propsz;
		pcount++;
	}
	*foffset = offset;

	return ret;
}

struct dtb_node* dtb_parse_data(void* dtb)	{
	struct dtb_header* header = (struct dtb_header*)dtb;
	uint32_t offset, lastoff, tmp;
	char* nodename, * strings = NULL;
	struct dtb_node* curr = NULL;

	offset = be_u32bits_to_cpu(header->off_dt_struct);
	lastoff = be_u32bits_to_cpu(header->size_dt_struct) + offset;

	strings = (char*)(dtb + be_u32bits_to_cpu(header->off_dt_strings));

	while(offset < lastoff)	{
		tmp = be_u32_to_cpu(dtb + offset);
		if(tmp == OF_DT_BEGIN_NODE)	{
			// Start of new node
		}
		else if(tmp == OF_DT_END_NODE)	{
			offset += 4;
			if(curr->parent != 0)
				curr = curr->parent;
			continue;
		}
		else if(tmp == OF_DT_END)	{
			break;
		}
		else	{
			printf("Invalid value: %i\n", tmp);
			while(1);
		}

		struct dtb_node* n = (void*)dtb_parse_node(dtb + offset + 4, strings, &tmp);
		n->numchilds = n->maxchilds = 0;
		n->childs = NULL;
		n->parent = curr;
		if(curr != NULL)	{
			if(curr->numchilds >= curr->maxchilds)	{
				curr->maxchilds += 10;
				curr->childs = (struct dtb_node**)realloc(curr->childs, (sizeof(void*) * curr->maxchilds) );
			}
			curr->childs[curr->numchilds++] = n;
		}
		curr = n;
		offset += 4 + tmp;
	}
	return curr;
}

uint64_t _dtb_parse_cell(void* data, uint32_t num)	{
	uint64_t ret = 0;
	ret = be_u32_to_cpu(data);
	if(num > 1)	{
		ret <<= 32;
		ret |= be_u32_to_cpu(data + 4);
	}
	return ret;
}

int _dtb_parse_reg(void* data, uint32_t acells, uint32_t scells, struct dtbreg* reg)	{
	reg->addr = _dtb_parse_cell(data, acells);
	reg->len = _dtb_parse_cell(data + (4 * acells), scells);
	return 0;
}

void _dtb_second_pass(struct dtb_node* n, uint32_t scells, uint32_t acells)	{
	int i;
	struct dtb_property* c;
	struct dtb_property tmp;

	// TODO: Should reorder so that '#' entries always are at the beginning

	for(i = 0; i < n->numprops; i++)	{
		c = &(n->props[i]);
		if(c->valsize == 0)	{
			c->type = EMPTY;
		}

		// Check if we can parse it as one 32-bit number
		else if(
			strcmp("#size-cells", c->name) == 0 ||
			strcmp("#gpio-cells", c->name) == 0 ||
			strcmp("#clock-cells", c->name) == 0 ||
			strcmp("#interrupt-cells", c->name) == 0 ||
			strcmp("#address-cells", c->name) == 0 ||
			strcmp("phandle", c->name) == 0 ||
			strcmp("virtual-reg", c->name) == 0 ||
			strcmp("msi-parent", c->name) == 0 ||
			strcmp("linux,initrd-start", c->name) == 0 ||
			strcmp("linux,initrd-end", c->name) == 0 ||
			strcmp("interrupt-parent", c->name) == 0

		)	{
			c->type = NUMBER;
			c->val.num = be_u32_to_cpu(c->data);

			// keep track of cell sizes so that we know how to parse reg values
			if(strcmp("#size-cells", c->name) == 0)		scells = c->val.num;
			if(strcmp("#address-cells", c->name) == 0)	acells = c->val.num;
		}
		else if(strcmp("compatible", c->name) == 0)	{
			// TODO: Maybe do this better
			// Can point to multiple strings separated by 1 NULL byte
			// 2 NULL bytes indicate full stop
			c->type = STRING;
			c->val.string = (char*)c->data;
		}
		else if(strcmp("status", c->name) == 0 ||
			strcmp("device_type", c->name) == 0||
			strcmp("stdout-path", c->name) == 0 ||
			strcmp("label", c->name) == 0 ||
			strcmp("clock-output-names", c->name) == 0 ||
			strcmp("method", c->name) == 0 ||
			strcmp("bootargs", c->name) == 0 ||
			strcmp("clock-names", c->name) == 0
		)	{
			c->type = STRING;
			c->val.string = (char*)c->data;
		}

		// Parse are integers or empty dataset
		// Just reverse the bytes and leave it alone
		else if(strcmp("ranges", c->name) == 0 ||
			strcmp("dma-ranges", c->name) == 0 ||
			strcmp("gpios", c->name) == 0 ||
			strcmp("reg", c->name) == 0 ||
			strcmp("interrupts", c->name) == 0 ||
			strcmp("interrupts-extended", c->name) == 0 ||
			strcmp("interrupt-map", c->name) == 0 ||
			strcmp("interrupt-map-mask", c->name) == 0
		)	{
			int i;
			c->val.ints = (uint32_t*)c->data;
			for(i = 0; i < c->valsize; i += 4)	{
				c->val.ints[i/4] = be_u32_to_cpu(c->data + i);
			}
			c->type = INTEGERS;

			// TODO: Can parse reg better, but cannot assume it only contains
			// one pair
			// ranges: Arbitrary number of triplets in the format:
			// (child-bus-address, parent-bus, length)
		}

		else if(strcmp("dma-coherent", c->name) == 0 ||
			strcmp("gpio-controller", c->name) == 0 ||
			strcmp("interrupt-controller", c->name) == 0
		)	{
			c->type = EMPTY;
		}
		else	{
			logd("Don't know how to parse %s\n", c->name);
		}
	}

	for(i = 0; i < n->numchilds; i++)	{
		_dtb_second_pass(n->childs[i], scells, acells);

	}
}

void dtb_second_pass(struct dtb_node* root)	{
	_dtb_second_pass(root, 1, 2);
}


struct dtb_node* _dtb_find_name(struct dtb_node* curr, const char* n, bool exact, int skip)	{
	int i;
	struct dtb_node* r = NULL;
	if((exact && strcmp(n, curr->name) == 0) || (!exact && strncmp(n, curr->name, strlen(n)) == 0))	{
		return curr;
	}
	for(i = 0; i < curr->numchilds; i++)	{
		r = _dtb_find_name(curr->childs[i], n, exact, skip);
		if(r != NULL)	{
			if(skip == 0)	return r;
			else			skip--;
		}
	}
	return NULL;

}

struct dtb_node* dtb_find_name(const char* n, bool exact, int skip)	{
	struct dtb_node* curr = cpu_get_parsed_dtb();
	return _dtb_find_name(curr, n, exact, skip);
}


int dtb_get_any(struct dtb_node* node, const char* name, enum dtb_type type)	{
	int i;
	for(i = 0; i < node->numprops; i++)	{
		if(strcmp(node->props[i].name, name) == 0)	{
			ASSERT_TRUE(node->props[i].type == type, "Surprising type");
			return i;
		}
	}
	return -1;
}

const char* dtb_get_string(struct dtb_node* node, const char* name)	{
	int i;
	i = dtb_get_any(node, name, STRING);
	if(i >= 0)	return node->props[i].val.string;
	return NULL;
}

const char* dtb_get_compatible(struct dtb_node* node)	{ 
	return dtb_get_string(node, "compatible"); 
}

uint32_t* dtb_get_ints(struct dtb_node* node, const char* name, int* count)	{
	int i;
	i = dtb_get_any(node, name, INTEGERS);
	if(i >= 0)	{
		*count = (node->props[i].valsize / 4);
		return node->props[i].val.ints;
	}
	return NULL;
}

int dtb_get_interrupts(struct dtb_node* node, uint32_t* type, uint32_t* nr, uint32_t* flags) {
	int count;
	uint32_t* res = dtb_get_ints(node, "interrupts", &count);
	if(res == NULL)	return -GENERAL_FAULT;

	*type = res[0];
	*nr = res[1];
	if(count > 2)	*flags = res[2];
	return count;
}

int dtb_get_as_reg(struct dtb_node* node, ptr_t* outaddr, ptr_t* outlen)	{
	int count;
	uint32_t* regs = dtb_get_ints(node, "reg", &count);
	ASSERT_TRUE(count == 4, "Unexpected count");

	*outaddr = regs[1] | (ptr_t)(regs[0]) << 32;
	*outlen = regs[3] | (ptr_t)(regs[2]) << 32;
	return count;
}

uint32_t dtb_get_int(struct dtb_node* node, const char* name)	{
	int i;
	i = dtb_get_any(node, name, NUMBER);
	if(i >= 0)	return node->props[i].val.num;
	return (uint32_t)-1;;
}

bool dtb_is_compatible(struct dtb_node* n, const char* c)	{
	int idx = 0;
	const char* comp = dtb_get_compatible(n);
	if(comp == NULL)	return false;

	while(comp[idx] != 0x00)	{
		if(strcmp(&comp[idx], c) == 0)	return true;
		idx += strlen(&comp[idx]) + 1;
	}
	return false;
}

void dtb_dump_compatible(struct dtb_node* n)	{
	int idx = 0, count = 0;
	const char* comp = dtb_get_compatible(n);
	printf("Compatible:\n");
	if(comp != NULL)	{
		while(comp[idx] != 0x00)	{
			printf("\t%i: %s\n", count, &(comp[idx]));
			idx += strlen( &(comp[idx]) ) + 1;
			count++;
		}
	}
}

