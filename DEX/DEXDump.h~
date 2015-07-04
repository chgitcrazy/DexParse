#ifndef _include_
#define _include_
#include<stdio.h>
#include<fcntl.h>
#include"Leb128.h"
#endif

#ifndef Dex_Struct
#define Dex_Struct

typedef struct DexHeader{
	ubyte    magic[8];
	uint     checksum;
	ubyte    siganature[20];
	uint     file_size;
	uint     header_size;
	uint     endian_tag;
	uint     link_size;
	uint     link_off;
	uint     map_off;
	uint     string_ids_size;
	uint     string_ids_off;
	uint     type_ids_size;
	uint     type_ids_off;
	uint     proto_ids_size;
	uint     proto_ids_off;
        uint     field_ids_size;
        uint     field_ids_off;
	uint     method_ids_size;
	uint     method_ids_off;
	uint     class_defs_size;
	uint     class_defs_off;
	uint     data_size;
	uint     data_off;
}D_Header;

typedef struct map_item
{
	ushort type;
	ushort unuse;
        uint size;
	uint offset;
}m_item;

typedef struct map_list
{
	uint  size;
        m_item list;
}m_list;

typedef struct string_ids_item
{
    uint string_data_off;
}s_ids_item;

typedef struct string_data_item
{
       uint size;
       ubyte data;
}s_data_item;

typedef struct type_ids_item
{
       uint descriptor_idx;
}t_ids_item;

typedef struct proto_id_item
{
  int  shorty_idx;
  int  return_type_idx;
  int  parameters_off;
}p_id_item;

typedef struct type_list
{
  int size;
  short int *type_idx;
}t_list;

typedef struct proto_string{
  char *shorty;
  char *return_type;
  char **parameter;
}p_string;

typedef struct field_id_item
{
   short int class_idx;
   short int type_idx;
   int   name_idx;
}f_id_item;

typedef struct field_string{
   char *field_class;
   char *field_type;
   char *field_name;
}f_string;

typedef struct method_id_item
{
short int  class_idx;
short int   proto_idx;
int    name_idx;
}m_id_item;

typedef struct method_string
{
   char *method_class;
   p_string method_proto;
   char *method_name;
}m_string;

typedef struct class_def_item
{
  int class_idx;
  int access_flags;
  int superclass_idx;
  int interfaces_off;
  int source_file_idx;
  int annotations_off;
  int class_data_off;
  int static_value_off;
}c_def_item;

typedef struct class_string
{
    char *class_type;
    uint access_flags;
    char *superclass_type;
    uint interface_off;
    char *source_file;
    uint annotation_off;
    uint class_data_off;
    uint static_value_off;
}c_string;

typedef struct encoded_field
{
int field_idx_diff; // index into filed_ids for ID of this filed
int access_flags; // access flags like public, static etc.
}en_field;

typedef struct encoded_method
{
int method_idx_diff;
int access_flags;
int code_off;
}en_method;


typedef struct class_data_item
{
   int static_fields_size;
   int instance_fields_size;
   int direct_methods_size;
   int virtual_methods_size;
   en_field *static_fields;
   en_field *instance_fields;
   en_method *direct_methods;
   en_method *virtual_methods;
}c_data_item;

typedef struct code_item {
    ushort  registersSize;
    ushort  insSize;
    ushort  outsSize;
    ushort  triesSize;
    uint  debugInfoOff;
    uint  insnsSize;
    ushort  insns[1];
}c_item;


#endif

#define MAX_SIZE 8000000

int ReadDexFile(int fd);
int OpenDex(char *filename);

















