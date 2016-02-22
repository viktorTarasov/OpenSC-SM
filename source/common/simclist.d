// D import file generated from 'simclist.d' renamed to 'simclist.d' (method [only for original == header file] results in very compact code and obviates to overhaul comments now)
// no functions

module common.simclist;
extern (C) 
{
	alias list_hash_t = int;
	alias element_comparator = int function(const(void)* a, const(void)* b);
	alias element_seeker = int function(const(void)* el, const(void)* indicator);
	alias element_meter = size_t function(const(void)* el);
	alias element_hash_computer = list_hash_t function(const(void)* el);
	alias element_serializer = void* function(const(void)* el, uint* serializ_len);
	alias element_unserializer = void* function(const(void)* data, uint* data_len);
	struct list_entry_s
	{
		void* data;
		list_entry_s* next;
		list_entry_s* prev;
	}
	struct list_attributes_s
	{
		element_comparator comparator;
		element_seeker seeker;
		element_meter meter;
		int copy_data;
		element_hash_computer hasher;
		element_serializer serializer;
		element_unserializer unserializer;
	}
	struct list_t
	{
		list_entry_s* head_sentinel;
		list_entry_s* tail_sentinel;
		list_entry_s* mid;
		uint numels;
		list_entry_s** spareels;
		uint spareelsnum;
		uint threadcount;
		int iter_active;
		uint iter_pos;
		list_entry_s* iter_curentry;
		list_attributes_s attrs;
	}
}
