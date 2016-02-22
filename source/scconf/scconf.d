// D import file generated from 'scconf.d' renamed to 'scconf.d' (method [only for original == header file] results in very compact code and obviates to overhaul comments now)
// Functions exported from "libopensc.*"

module scconf.scconf;
extern (C) 
{
	struct scconf_entry
	{
		const(char)* name;
		uint type;
		uint flags;
		void* parm;
		void* arg;
	}
	enum 
	{
		SCCONF_PRESENT = 1,
		SCCONF_MANDATORY = 2,
		SCCONF_ALLOC = 4,
		SCCONF_ALL_BLOCKS = 8,
		SCCONF_VERBOSE = 16,
	}
	enum 
	{
		SCCONF_CALLBACK = 1,
		SCCONF_BLOCK = 2,
		SCCONF_LIST = 3,
		SCCONF_BOOLEAN = 11,
		SCCONF_INTEGER = 12,
		SCCONF_STRING = 13,
	}
	alias scconf_block = _scconf_block;
	struct scconf_list
	{
		scconf_list* next;
		char* data;
	}
	enum 
	{
		SCCONF_ITEM_TYPE_COMMENT = 0,
		SCCONF_ITEM_TYPE_BLOCK = 1,
		SCCONF_ITEM_TYPE_VALUE = 2,
	}
	struct scconf_item
	{
		scconf_item* next;
		int type;
		char* key;
		union anonymous
		{
			char* comment;
			scconf_block* block;
			scconf_list* list;
		}
		anonymous value;
	}
	struct _scconf_block
	{
		scconf_block* parent;
		scconf_list* name;
		scconf_item* items;
	}
	struct scconf_context
	{
		char* filename;
		int debug_;
		scconf_block* root;
		char* errmsg;
	}
	extern scconf_context* scconf_new(const(char)* filename);
	extern void scconf_free(scconf_context* config);
	extern int scconf_parse(scconf_context* config);
	extern int scconf_parse_string(scconf_context* config, const(char)* string);
	extern int scconf_parse_entries(const(scconf_context)* config, const(scconf_block)* block, scconf_entry* entry);
	extern int scconf_write(scconf_context* config, const(char)* filename);
	extern int scconf_write_entries(scconf_context* config, scconf_block* block, scconf_entry* entry);
	extern const(scconf_block)* scconf_find_block(const(scconf_context)* config, const(scconf_block)* block, const(char)* item_name);
	extern scconf_block** scconf_find_blocks(const(scconf_context)* config, const(scconf_block)* block, const(char)* item_name, const(char)* key);
	extern const(scconf_list)* scconf_find_list(const(scconf_block)* block, const(char)* option);
	extern const(char)* scconf_get_str(const(scconf_block)* block, const(char)* option, const(char)* def);
	extern int scconf_get_int(const(scconf_block)* block, const(char)* option, int def);
	extern int scconf_get_bool(const(scconf_block)* block, const(char)* option, int def);
	extern const(char)* scconf_put_str(scconf_block* block, const(char)* option, const(char)* value);
	extern int scconf_put_int(scconf_block* block, const(char)* option, int value);
	extern int scconf_put_bool(scconf_block* block, const(char)* option, int value);
	extern scconf_block* scconf_block_add(scconf_context* config, scconf_block* block, const(char)* key, const(scconf_list)* name);
	extern scconf_block* scconf_block_copy(const(scconf_block)* src, scconf_block** dst);
	extern void scconf_block_destroy(scconf_block* block);
	extern scconf_item* scconf_item_add(scconf_context* config, scconf_block* block, scconf_item* item, int type, const(char)* key, const(void)* data);
	extern scconf_item* scconf_item_copy(const(scconf_item)* src, scconf_item** dst);
	extern void scconf_item_destroy(scconf_item* item);
	extern scconf_list* scconf_list_add(scconf_list** list, const(char)* value);
	extern scconf_list* scconf_list_copy(const(scconf_list)* src, scconf_list** dst);
	extern void scconf_list_destroy(scconf_list* list);
	extern int scconf_list_array_length(const(scconf_list)* list);
	extern int scconf_list_strings_length(const(scconf_list)* list);
	extern char* scconf_list_strdup(const(scconf_list)* list, const(char)* filler);
	extern const(char)** scconf_list_toarray(const(scconf_list)* list);
}
