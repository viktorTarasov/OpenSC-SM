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

	scconf_context* scconf_new(const(char)* filename);
	void scconf_free(scconf_context* config);
	int scconf_parse(scconf_context* config);
	int scconf_parse_string(scconf_context* config, const(char)* string);
	int scconf_parse_entries(const(scconf_context)* config, const(scconf_block)* block, scconf_entry* entry);
	int scconf_write(scconf_context* config, const(char)* filename);
	int scconf_write_entries(scconf_context* config, scconf_block* block, scconf_entry* entry);
	const(scconf_block)* scconf_find_block(const(scconf_context)* config, const(scconf_block)* block, const(char)* item_name);
	scconf_block** scconf_find_blocks(const(scconf_context)* config, const(scconf_block)* block, const(char)* item_name, const(char)* key);
	const(scconf_list)* scconf_find_list(const(scconf_block)* block, const(char)* option);
	const(char)* scconf_get_str(const(scconf_block)* block, const(char)* option, const(char)* def);
	int scconf_get_int(const(scconf_block)* block, const(char)* option, int def);
	int scconf_get_bool(const(scconf_block)* block, const(char)* option, int def);
	const(char)* scconf_put_str(scconf_block* block, const(char)* option, const(char)* value);
	int scconf_put_int(scconf_block* block, const(char)* option, int value);
	int scconf_put_bool(scconf_block* block, const(char)* option, int value);
	scconf_block* scconf_block_add(scconf_context* config, scconf_block* block, const(char)* key, const(scconf_list)* name);
	scconf_block* scconf_block_copy(const(scconf_block)* src, scconf_block** dst);
	void scconf_block_destroy(scconf_block* block);
	scconf_item* scconf_item_add(scconf_context* config, scconf_block* block, scconf_item* item, int type, const(char)* key, const(void)* data);
	scconf_item* scconf_item_copy(const(scconf_item)* src, scconf_item** dst);
	void scconf_item_destroy(scconf_item* item);
	scconf_list* scconf_list_add(scconf_list** list, const(char)* value);
	scconf_list* scconf_list_copy(const(scconf_list)* src, scconf_list** dst);
	void scconf_list_destroy(scconf_list* list);
	int scconf_list_array_length(const(scconf_list)* list);
	int scconf_list_strings_length(const(scconf_list)* list);
	char* scconf_list_strdup(const(scconf_list)* list, const(char)* filler);
	const(char)** scconf_list_toarray(const(scconf_list)* list);
}
