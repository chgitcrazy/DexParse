#include "DEXDump.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//dex文件头
static D_Header d_header;

//dex Map映射
static m_list   mlist;
static m_item   *mitem;

//dex字符串
static s_ids_item *str_off_item;
static s_data_item * str_item;

//dex类型
static t_ids_item *type_item;

//dex方法原型
static p_id_item *p_item;
static t_list type_list;

//dex字段
static f_id_item *field_item;

//dex方法
static m_id_item *method_item;

//dex类
static c_def_item *class_item;
static c_data_item class_data_item;

int OpenDex(char *filename)
{
     int fd;
     //open the file with read-only mode
     fd = open(filename,O_RDONLY);
     if(fd == -1)
     {
       printf("Open %s Error!\n",filename);
     }
     return fd;
}

void output(char *str)
{
     int x = 0x42af8028;
     for(int i = 0; i < 1000; i++)
     {
          
          if ( i != 0 && i % 4 == 0)
          {
          printf("\n");
          printf("0x%8x:  ",x);
          x += 4;
          printf("0x%8x  ",*((int *)&str[i * 4]));
          
          }
          else
          {
          printf("0x%8x  ",*((int *)&str[i * 4]));
          }
          
          
      
     }
}


int ReadDexFile(int fd)
{
    ubyte str[MAX_SIZE]; 
    int num = read(fd,str,MAX_SIZE);
    printf("num:%d\n",num);
    //output(str);
    if(num != 0)
    {
     
       /*check the file format 
        *dex:0x64 0x65 0x78 0x0a 0x30 0x33 0x35 0x00
        *odex:0x64 0x65 0x79 0x0a 0x30 0x33 0x36 0x00
        */ 
       if(*((int *)&str[0]) == 0x0a786564 && *((int *)&str[4]) == 0x00353330)
       {
//read the header
              printf("0.read the header..........\n");
              for(int i = 0; i < 8; i++)
              {
                  d_header.magic[i] = str[i];
              }
              printf("magic:");
              for(int i = 0; i < 8; i++)
              {
                  if(d_header.magic[i] == 0xa)
                  {
                     printf("\\");
                     printf("n");
                  }
                  else if(d_header.magic[i] == 0x0)
                  {
                     printf("\\");
                     printf("0");
                  }
                  else
                  {
                      printf("%c",d_header.magic[i]);
                  }
              }
              printf("\n");

              d_header.checksum = *((int *)&str[8]);
              printf("checksum:0x%x  \n",d_header.checksum);

              printf("signature:0x%x 0x%x 0x%x 0x%x 0x%x\n",*((int *)&str[12]),*((int *)&str[16]),*((int *)&str[20]),*((int *)&str[24]),*((int *)&str[28]));

              d_header.file_size = *((int *)&str[32]);
              printf("filesize:0x%x  \n",d_header.file_size);

              d_header.header_size = *((int *)&str[36]);
              printf("headersize:0x%x  \n",d_header.header_size);

               d_header.endian_tag = *((int *)&str[40]);
              printf("endian:0x%x  \n", d_header.endian_tag);

              d_header.link_size = *((int *)&str[44]);
              printf("link_size:0x%x  \n", d_header.link_size);
    
              d_header.link_off = *((int *)&str[48]);
              printf("link_off:0x%x  \n", d_header.link_off);

              d_header.map_off = *((int *)&str[52]);
              printf("map_off:0x%x  \n", d_header.map_off);
 
              d_header.string_ids_size = *((int *)&str[56]);
              printf("string_ids_size:0x%x  \n", d_header.string_ids_size);

              d_header.string_ids_off = *((int *)&str[60]);
              printf("string_ids_off:0x%x  \n", d_header.string_ids_off);

              d_header.type_ids_size = *((int *)&str[64]);
              printf("type_ids_size:0x%x  \n", d_header.type_ids_size);

              d_header.type_ids_off = *((int *)&str[68]);
              printf("type_ids_off:0x%x  \n", d_header.type_ids_off);

              d_header.proto_ids_size = *((int *)&str[72]);
              printf("proto_ids_size:0x%x  \n", d_header.proto_ids_size);

              d_header.proto_ids_off = *((int *)&str[76]);
              printf("proto_ids_off:0x%x  \n", d_header.proto_ids_off);

              d_header.field_ids_size = *((int *)&str[80]);
              printf("field_ids_size:0x%x  \n", d_header.field_ids_size);

              d_header.field_ids_off = *((int *)&str[84]);
              printf("field_ids_off:0x%x  \n", d_header.field_ids_off);

              d_header.method_ids_size = *((int *)&str[88]);
              printf("method_ids_size:0x%x  \n", d_header.method_ids_size);

              d_header.method_ids_off = *((int *)&str[92]);
              printf("method_ids_off:0x%x  \n", d_header.method_ids_off);

              d_header.class_defs_size = *((int *)&str[96]);
              printf("class_defs_size:0x%x  \n", d_header.class_defs_size);

              d_header.class_defs_off = *((int *)&str[100]);
              printf("class_defs_off:0x%x  \n", d_header.class_defs_off);

              d_header.data_size = *((int *)&str[104]);
              printf("data_size:0x%x  \n", d_header.data_size);

              d_header.data_off = *((int *)&str[108]);
              printf("data_off:0x%x  \n", d_header.data_off);

/*
//read the map_list
printf("\n\n");
printf("1. read the map list.........\n");
       mlist.size = *((int *)&str[d_header.map_off]);
       printf("map item size:0x%x  \n",mlist.size);
      
       mitem =  (m_item *)malloc(sizeof(m_item) *  mlist.size);
       
       int addr = d_header.map_off + 4;
       for(int i = 0; i< mlist.size; i++)
       {
           mitem[i].type = *((ushort *)&str[addr]);
           mitem[i].unuse = *((ushort *)&str[addr + 2]);
           mitem[i].size = *((uint *)&str[addr + 4]);
           mitem[i].offset = *((uint *)&str[addr + 8]);
           addr += 12;
       }
       
       for(int i = 0; i< mlist.size; i++)
       {
           switch(mitem[i].type){
                case 0x0:
                     printf("Item type:  header_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x1:
                     printf("Item type:  string_id_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x2:
                     printf("Item type:  type_id_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x3:
                     printf("Item type:  proto_id_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x4:
                     printf("Item type:  field_id_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x5:
                     printf("Item type:  method_id_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x6:
                     printf("Item type:  class_def_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x1000:
                     printf("Item type:  map_list_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x1001:
                     printf("Item type:  type_list_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x1002:
                     printf("Item type:  annotation_set_ref\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x1003:
                     printf("Item type:  anntation_set_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x2000:
                     printf("Item type:  class_data_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x2001:
                     printf("Item type:  code_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x2002:
                     printf("Item type:  string_data_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x2003:
                     printf("Item type:  debug_info_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x2004:
                     printf("Item type:  annotation_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x2005:
                     printf("Item type:  encoded_array_item\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
 break;
                case 0x2006:
                     printf("Item type:  annotations_direct\n");
                     printf("Item size:0x%x  \n",mitem[i].size);
                     printf("Item offset:0x%x  \n",mitem[i].offset);
                     break;
                 
           }
       }*/

            char **type_type_list = (char **)malloc(d_header.type_ids_size);
              char **save_proto = (char **)malloc(d_header.proto_ids_size);
              ubyte **save_string = malloc(d_header.string_ids_size);
//reading the string
printf("\n\n");
printf("2. reading the string....\n");   
              int increament = 0;
              str_item = (s_data_item *)malloc(sizeof(s_data_item) * d_header.string_ids_size);
              str_off_item = (s_ids_item*)malloc(sizeof(s_ids_item) * d_header.string_ids_size);   
              for(int i = 0; i < d_header.string_ids_size; i++)
              {
                  str_off_item[i].string_data_off = *((int *)&str[d_header.string_ids_off + increament]);
                  ubyte* t = (ubyte*)&str[str_off_item[i].string_data_off];
                  ubyte** tt = &t;
                  str_item[i].size = readUnsignedLeb128(tt);
                  str_item[i].data = **tt;
                  if(str_item[i].size != 0)
                  {
                     save_string[i] = malloc(str_item[i].size * sizeof(ubyte));
                  }           
                  printf("index:0x%x ====>",i); 
                  save_string[i] = *tt;
                  printf("%s\n",save_string[i]);
                  increament += 4;
              }
  
              
//reading the type
printf("\n\n");
printf("3. reading the type.....\n");
              increament = 0;
              type_item = (t_ids_item*)malloc(sizeof(t_ids_item) * d_header.type_ids_size);
              for(int i = 0; i < d_header.type_ids_size; i++)
              {
                    type_item[i].descriptor_idx = *((int *)&str[d_header.type_ids_off + increament]);
                    type_type_list[i] = save_string[type_item[i].descriptor_idx];
                    printf("%s\n",type_type_list[i]);
                    increament += 4;
              }


//reading the proto type
printf("\n\n");
printf("4. reading the proto.....\n");           
              int off =  d_header.proto_ids_off;
              p_item = (p_id_item*)malloc(sizeof(p_id_item) * d_header.proto_ids_size);
              for(int i = 0;i < d_header.proto_ids_size; i++)
              {
                   p_item[i].shorty_idx = *((int *)&str[off]);
                   printf("0x%x<===>",p_item[i].shorty_idx);
                   printf("%s<===>",save_string[p_item[i].shorty_idx]);
                   p_item[i].return_type_idx = *((int *)&str[off + 4]);
                   printf("0x%x<===>",p_item[i].return_type_idx);
                   printf("%s<===>",type_type_list[p_item[i].return_type_idx]);
                   p_item[i].parameters_off = *((int *)&str[off + 8]);
                   if(p_item[i].parameters_off != 0)
                   {
                        type_list.size = *((int *)&str[p_item[i].parameters_off]);
                        int k = 0;
		        for(int j = 0; j < type_list.size; j++)
		        {
		            printf("parameter type:%s\n",type_type_list[*((ushort *)&str[p_item[i].parameters_off + 4 + k])]);
		            k += 2;
		        }
                        
                   }
                   off += 12;
                   printf("\n");
              }


//reading the field 
printf("\n\n");     
printf("5. reading the field.....\n");
           int addr = d_header.field_ids_off;
           field_item = (f_id_item*)malloc(d_header.field_ids_size * sizeof(f_id_item));
           for(int i = 0; i < d_header.field_ids_size ; i++)
           {
                 field_item[i].class_idx = *((ushort*)&str[addr]);
                 printf("%s<===>",type_type_list[field_item[i].class_idx]);
                 field_item[i].type_idx = *((ushort*)&str[addr + 2]);
                 printf("%s<===>",type_type_list[field_item[i].type_idx]);
                 field_item[i].name_idx = *((uint*)&str[addr + 4]);       
                 printf("%s\n",save_string[field_item[i].name_idx]);
                 addr += 8;
           }

 
//reading the method
printf("\n\n");     
printf("6. reading the method....\n");
           method_item = (m_id_item*)malloc(d_header.method_ids_size * sizeof(m_id_item));
           addr = d_header.method_ids_off;
           for(int i = 0; i < d_header.method_ids_size ; i++)
           {
                 method_item[i].class_idx = *((short int *)&str[addr]);
                 printf("%s<==>",type_type_list[method_item[i].class_idx]);
                 method_item[i].proto_idx = *((short int *)&str[addr + 2]);
                 printf("%s",save_string[p_item[method_item[i].proto_idx].shorty_idx]);
                 
                  /* if(p_item[method_item[i].proto_idx].parameters_off != 0)
                   {
                        int offset = *((int *)&str[p_item[i].parameters_off]);
                        int k = 0;
		        for(int j = 0; j < offset; j++)
		        {
		            printf("(%s)",type_type_list[*((ushort *)&str[p_item[method_item[i].proto_idx].parameters_off + 4 + k])]);
		            k += 2;
		        }
                        
                   }
                   else{
                       printf("()");
                   }*/
                 
                 printf("%s<==>",type_type_list[p_item[method_item[i].proto_idx].return_type_idx]);
                 method_item[i].name_idx = *((int *)&str[addr + 4]);       
                 printf("%s\n",save_string[method_item[i].name_idx]);
                 addr += 8;
           }

//reading the class
printf("\n\n");
printf("7. reading the class define....\n");
          addr = d_header.class_defs_off;
          class_item = (c_def_item*)malloc(sizeof(c_def_item) * d_header.class_defs_size);
          for(int i = 0; i < d_header.class_defs_size; i++)
          {
                class_item[i].class_idx = *((int *)&str[addr]);
                printf("%s\n",type_type_list[class_item[i].class_idx]);
                class_item[i].access_flags = *((int *)&str[addr + 4]);
                switch(class_item[i].access_flags){
                     case 0x00000001:
                     printf("ACC_PUBLIC ");break;
                     case 0x00000002:
                     printf("ACC_PRIVATE");break;
                     case 0x00000004:
                     printf("ACC_PROTECTED");break;
                     case 0x00000008:
                     printf("ACC_STATIC ");break;
                     case 0x00000010:
                     printf("ACC_FINAL ");break;
                     case 0x00000021:
                     printf("ACC_SYNCHRONIZED");break;
                     case 0x00000020:
                     printf("ACC_SUPER ");break;
                     case 0x00000040:
                     printf("ACC_VOLATILE");break;
                     case 0x00000041:
                     printf("ACC_BRIDGE");break;
                     case 0x00000081:
                     printf("ACC_TRANSIENT");break;
                     case 0x00000080:
                     printf("ACC_VARARGS");break;
                     case 0x00000100:
                     printf("ACC_NATIVE");break;
                     case 0x00000200:
                     printf("ACC_INTERFACE");break;
                     case 0x00000400:
                     printf("ACC_ABSTRACT");break;
                     case 0x00000800:
                     printf("ACC_STRICT");break;
                     case 0x00001000:
                     printf("ACC_SYNTHETIC");break;
                     case 0x00002000:
                     printf(" ACC_ANNOTATION");break;
                     case 0x00004000:
                     printf("ACC_ENUM");break;
                     case 0x00010000:
                     printf("ACC_CONSTRUCTOR ");break;
                     case 0x00020000:
                     printf("ACC_DECLARED_SYNCHRONIZED");break;
                     default:
                     printf("0x%x:",class_item[i].access_flags);
                     
                }
                printf("\n");
                class_item[i].superclass_idx = *((int *)&str[addr + 8]);
                printf("%s\n",type_type_list[class_item[i].superclass_idx]);
                class_item[i].interfaces_off = *((int *)&str[addr + 12]);
                printf("class_item.interfaces_off:0x%x\n",class_item[i].interfaces_off);
                class_item[i].source_file_idx = *((int *)&str[addr + 16]);
                printf("%s\n",save_string[class_item[i].source_file_idx]);
                class_item[i].annotations_off = *((int *)&str[addr + 20]); 
                printf("class_item.annotations_off:0x%x\n",class_item[i].annotations_off);
                class_item[i].class_data_off = *((int *)&str[addr + 24]);
                printf("class_item.class_data_off:0x%x\n",class_item[i].class_data_off);
                class_item[i].static_value_off = *((int *)&str[addr + 28]);
                printf("class_item.static_value_off:0x%x\n",class_item[i].static_value_off);
                addr += 32;
                printf("\n");
           } 
   
           printf("\n");
           int *class_static_fields_size = (int *)malloc(sizeof(int) * d_header.class_defs_size);
           int *class_instance_fields_size = (int *)malloc(sizeof(int) * d_header.class_defs_size);
           int *class_directive_methods_size = (int *)malloc(sizeof(int) * d_header.class_defs_size);
           int *class_virtual_methods_size = (int *)malloc(sizeof(int) * d_header.class_defs_size);
           
           en_field *static_fields;
           en_field *instance_fields;
           en_method *directive_methods;
           en_method *virtual_methods;
           for(int i = 0; i < d_header.class_defs_size; i++)
           {
               
                ubyte *t = (ubyte *)&str[class_item[i].class_data_off];
                ubyte **tt = &t;
                class_static_fields_size[i] = readUnsignedLeb128(tt);
                class_instance_fields_size[i] = readUnsignedLeb128(tt);
                class_directive_methods_size[i] = readUnsignedLeb128(tt);
                class_virtual_methods_size[i] = readUnsignedLeb128(tt);
                printf("    static_fields_size: 0x%x\n",class_static_fields_size[i]);
                printf("    instance_fields_size: 0x%x\n",class_instance_fields_size[i]);
                printf("    directive_methods_size: 0x%x\n",class_directive_methods_size[i]);
                printf("    virtual_methods_size: 0x%x\n",class_virtual_methods_size[i]);
                printf("\n");

                if(class_static_fields_size[i] != 0)
                {
                    static_fields = (en_field *)malloc(sizeof(en_field) * class_static_fields_size[i]);
                    for(int k1 = 0; k1 < class_static_fields_size[i]; k1++)
                    {  
                         static_fields[k1].field_idx_diff = readUnsignedLeb128(tt);
                         static_fields[k1].access_flags = readUnsignedLeb128(tt);
                         printf("      static_filed_idx_diff:0x%x   \n",static_fields[k1].field_idx_diff);
                         printf("      static_access_flags:0x%x   \n",static_fields[k1].access_flags);
                         printf("\n");
                    }
                }
                printf("\n");
                if(class_instance_fields_size[i] != 0)
                {
                    instance_fields = (en_field *)malloc(sizeof(en_field) * class_instance_fields_size[i]);
                    for(int k2 = 0; k2 < class_instance_fields_size[i]; k2++)
                    {
                         instance_fields[k2].field_idx_diff = readUnsignedLeb128(tt);
                         instance_fields[k2].access_flags = readUnsignedLeb128(tt);
                         printf("      instance_filed_idx_diff:0x%x   \n",instance_fields[k2].field_idx_diff);
                         printf("      instance_access_flags:0x%x   \n",instance_fields[k2].access_flags);
                         printf("\n");
                    }
                }
                printf("\n");
                if(class_directive_methods_size[i] != 0)
                {
                    directive_methods = (en_method *)malloc(sizeof(en_method) * class_directive_methods_size[i]);
                    c_item *direct_code_info = (c_item*)malloc(sizeof(c_item) * class_directive_methods_size[i]); 
                    for(int k3 = 0; k3 < class_directive_methods_size[i]; k3++)
                    {
                        
                         directive_methods[k3].method_idx_diff = readUnsignedLeb128(tt);
                         directive_methods[k3].access_flags = readUnsignedLeb128(tt);
                         directive_methods[k3].code_off = readUnsignedLeb128(tt);
                         direct_code_info[k3].registersSize = *((ushort*)&str[directive_methods[k3].code_off]);
                         direct_code_info[k3].insSize = *((ushort*)&str[directive_methods[k3].code_off + 2]);
                         direct_code_info[k3].outsSize = *((ushort*)&str[directive_methods[k3].code_off + 4]);
                         direct_code_info[k3].triesSize = *((ushort*)&str[directive_methods[k3].code_off + 6]);
                         direct_code_info[k3].debugInfoOff = *((ushort*)&str[directive_methods[k3].code_off + 8]);
                         direct_code_info[k3].insnsSize = *((ushort*)&str[directive_methods[k3].code_off + 12]);
                         direct_code_info[k3].insns[0] = *((ushort*)&str[directive_methods[k3].code_off + 16]);
                         int tempCount = direct_code_info[k3].insnsSize;
                         int tempAddr = directive_methods[k3].code_off + 16;
                         printf("      directive_method_idx_diff:0x%x   \n",directive_methods[k3].method_idx_diff);
                         printf("      directive_access_flags:0x%x   \n",directive_methods[k3].access_flags);
                         printf("      directive_code_off:0x%x   \n",directive_methods[k3].code_off);
                         printf("        code:");
                         
                         for(int i = 0 ; i < tempCount; i++)
                         {
                                printf("0x%x ",*((ushort*)&str[tempAddr]));
                                tempAddr += 2;
                         } 
                         printf("\n\n");     
                         
                         
                    }
                }
                printf("\n");
                if(class_virtual_methods_size[i] != 0)
                {
                    virtual_methods = (en_method *)malloc(sizeof(en_method) * class_virtual_methods_size[i]);
                    for(int k4 = 0; k4 < class_virtual_methods_size[i]; k4++)
                    {
                         virtual_methods[k4].method_idx_diff = readUnsignedLeb128(tt);
                         virtual_methods[k4].access_flags = readUnsignedLeb128(tt);
                         virtual_methods[k4].code_off = readUnsignedLeb128(tt);
                         printf("      virtual_method_idx_diff:0x%x   \n",virtual_methods[k4].method_idx_diff);
                         printf("      virtual_access_flags:0x%x   \n", virtual_methods[k4].access_flags);
                         printf("      virtual_code_off:0x%x   \n", virtual_methods[k4].code_off);
                         printf("\n");
                    }
                }   
           }
              
       }

    else
    {
        printf("this file is not 'dex' format");
    }
  }
}  
