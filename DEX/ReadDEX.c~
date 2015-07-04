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


char **type_type_list;
ubyte **save_string;
p_string *prototype_string;
f_string *fieldinfo_string;
m_string *methodinfo_string;
c_string *classinfo_string;

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

               type_type_list = (char **)malloc(d_header.type_ids_size * sizeof(char *));
               save_string = (ubyte**)malloc(d_header.string_ids_size * sizeof(ubyte*));
               prototype_string = (p_string*)malloc(sizeof(p_string) * d_header.proto_ids_size);
               fieldinfo_string = (f_string*)malloc(sizeof(f_string) * d_header.field_ids_size);
               methodinfo_string = (m_string*)malloc(sizeof(m_string) * d_header.method_ids_size);
               classinfo_string = (c_string*)malloc(sizeof(c_string) * d_header.class_defs_size);
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
                    printf("index:0x%x ====>",i); 
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
                   prototype_string[i].shorty = save_string[p_item[i].shorty_idx];
                   p_item[i].return_type_idx = *((int *)&str[off + 4]);
                   prototype_string[i].return_type = type_type_list[p_item[i].return_type_idx];
                   p_item[i].parameters_off = *((int *)&str[off + 8]);
                   if(p_item[i].parameters_off != 0)
                   {
                        type_list.size = *((int *)&str[p_item[i].parameters_off]);
                        //prototype_string[i].parameter = (char**)malloc(type_list.size * sizeof(char*));
                        int k = 0;
                                char **param_string = (char**)malloc(type_list.size * sizeof(char*));
		                for(int j = 0; j < type_list.size; j++)
		                {
                                    param_string[j] = type_type_list[*((ushort *)&str[p_item[i].parameters_off + 4 + k])];
		                    k += 2;
                                    
		                }
                                prototype_string[i].parameter = param_string;
                   }
                   off += 12;
              }
             
              /*for(int i = 0; i < d_header.proto_ids_size; i++)
              {    
                   printf("%s<==>%s<==>",prototype_string[i].shorty,prototype_string[i].return_type);
                   if(p_item[i].parameters_off != 0){
		           for(int p = 0; p < *((int *)&str[p_item[i].parameters_off]); p++)
		           { 
		               printf("%s:",prototype_string[i].parameter[p]);
		           }
		           printf("\n");
                   }
                   else{
                           printf("\n");
                   }
              }*/


//reading the field 
printf("\n\n");     
printf("5. reading the field.....\n");
           int addr = d_header.field_ids_off;
           field_item = (f_id_item*)malloc(d_header.field_ids_size * sizeof(f_id_item));
           for(int i = 0; i < d_header.field_ids_size ; i++)
           {
                 field_item[i].class_idx = *((ushort*)&str[addr]);
                 fieldinfo_string[i].field_class = type_type_list[field_item[i].class_idx];
                 field_item[i].type_idx = *((ushort*)&str[addr + 2]);
                 fieldinfo_string[i].field_type=type_type_list[field_item[i].type_idx];
                 field_item[i].name_idx = *((uint*)&str[addr + 4]); 
                 fieldinfo_string[i].field_name=save_string[field_item[i].name_idx];   
                 addr += 8;
           }

           for(int i = 0; i < d_header.field_ids_size; i++)
           {
                printf("field index:0x%x:",i);
                printf("%s->%s:%s\n",fieldinfo_string[i].field_class,fieldinfo_string[i].field_name,fieldinfo_string[i].field_type);
           }

 
//reading the method
printf("\n\n");     
printf("6. reading the method....\n");
           method_item = (m_id_item*)malloc(d_header.method_ids_size * sizeof(m_id_item));
           addr = d_header.method_ids_off;
           for(int i = 0; i < d_header.method_ids_size ; i++)
           {
                 method_item[i].class_idx = *((short int *)&str[addr]);
                 methodinfo_string[i].method_class = type_type_list[method_item[i].class_idx];
                 method_item[i].proto_idx = *((short int *)&str[addr + 2]);
                 methodinfo_string[i].method_proto = prototype_string[method_item[i].proto_idx];
                 method_item[i].name_idx = *((int *)&str[addr + 4]); 
                 methodinfo_string[i].method_name = save_string[method_item[i].name_idx];
                 addr += 8;
           }

            for(int i = 0; i < d_header.method_ids_size ; i++)
            {
                 //if(strcmp(methodinfo_string[i].method_class,"Lcom/example/hellojni/HelloJni;") == 0){
                 printf("[0x%x]:",i);
                 printf("%s->%s:%s\n",methodinfo_string[i].method_class,methodinfo_string[i].method_name,methodinfo_string[i].method_proto.return_type);
                 //}
            }



//reading the class
printf("\n\n");
printf("7. reading the class define....\n");
          addr = d_header.class_defs_off;
          class_item = (c_def_item*)malloc(sizeof(c_def_item) * d_header.class_defs_size);
          for(int i = 0; i < d_header.class_defs_size; i++)
          {
                class_item[i].class_idx = *((int *)&str[addr]);
                classinfo_string[i].class_type = type_type_list[class_item[i].class_idx];
                class_item[i].access_flags = *((int *)&str[addr + 4]);
                classinfo_string[i].access_flags = class_item[i].access_flags;
                class_item[i].superclass_idx = *((int *)&str[addr + 8]);
                classinfo_string[i].superclass_type = type_type_list[class_item[i].superclass_idx];
                class_item[i].interfaces_off = *((int *)&str[addr + 12]);
                classinfo_string[i].interface_off = class_item[i].interfaces_off;
                class_item[i].source_file_idx = *((int *)&str[addr + 16]);
                classinfo_string[i].source_file = save_string[class_item[i].source_file_idx];
                class_item[i].annotations_off = *((int *)&str[addr + 20]); 
                classinfo_string[i].annotation_off = class_item[i].annotations_off;
                class_item[i].class_data_off = *((int *)&str[addr + 24]);
                classinfo_string[i].class_data_off = class_item[i].class_data_off;
                class_item[i].static_value_off = *((int *)&str[addr + 28]);
                classinfo_string[i].static_value_off = class_item[i].static_value_off;
                addr += 32;
           } 

            for(int i = 0; i < d_header.class_defs_size; i++)
            {
                 if(strcmp(classinfo_string[i].class_type,"Lcom/example/hellojni/HelloJni;") == 0){
                 printf("data_off:0x%x\n",classinfo_string[i].class_data_off);
                 printf("[0x%x]",i);
                 if(class_item[i].source_file_idx != 0xffffffff){
                 printf("%s in %s, super:%s\n",classinfo_string[i].class_type,classinfo_string[i].source_file,classinfo_string[i].superclass_type);}
                 else{
                 printf("%s in undefined, super:%s\n",classinfo_string[i].class_type,classinfo_string[i].superclass_type);}
                 }
                 }
            }
   
           
     
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

              if(strcmp(classinfo_string[i].class_type,"Lcom/example/hellojni/HelloJni;") == 0)
              {
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
                    int method_index = 0;
                    for(int k3 = 0; k3 < class_directive_methods_size[i]; k3++)
                    {
                         directive_methods[k3].method_idx_diff = readUnsignedLeb128(tt) + method_index;
                         method_index =  directive_methods[k3].method_idx_diff;
                         directive_methods[k3].access_flags = readUnsignedLeb128(tt);
                         directive_methods[k3].code_off = readUnsignedLeb128(tt);  
                         printf("      directive_method_idx_diff:0x%x\n",directive_methods[k3].method_idx_diff); 
                         printf("      directive_access_flags:0x%x\n",directive_methods[k3].access_flags);
		         printf("      directive_code_off:0x%x\n",directive_methods[k3].code_off);
                         int tempCount = *((uint*)&str[directive_methods[k3].code_off + 12]);
                         int tempAddr = directive_methods[k3].code_off + 16;
                         printf("            tempCount:0x%x\n",tempCount);
                         printf("            tempAddr:0x%x\n",tempAddr);
                         if( directive_methods[k3].method_idx_diff < d_header.method_ids_size){
                         printf("      methodName:%s\n",methodinfo_string[directive_methods[k3].method_idx_diff].method_name);
                         }
                         else{
                         printf("      methodName:undefined\n");
                         }     
		         printf("      code:\n"); 
                         if(tempCount < d_header.file_size && tempCount * 2 + tempAddr < d_header.file_size){ 
                           printf("        ");  
                           //int tempAddr1 = tempAddr;
		           for(int i = 0 ; i < tempCount; i++)
		           {
		              printf("0x%x ",*((ushort*)&str[tempAddr]));
		              tempAddr += 2;
		           }
                           /*printf("\n");
                           printf("      code1\n");
                           for(int i = 0 ; i < tempCount * 2; i++)
		           {
		              printf("0x%x ",*((ubyte*)&str[tempAddr1]));
		              tempAddr1 += 1;
		           }*/
                         }else{
                            printf("too big\n");
                         }
		         printf("\n\n");
                     }
                }

                printf("\n");
                
                if(class_virtual_methods_size[i] != 0)
                {
                      int method_index = 0;
                      virtual_methods = (en_method *)malloc(sizeof(en_method) * class_virtual_methods_size[i]);
                      c_item *virtual_code_info = (c_item*)malloc(sizeof(c_item) * class_virtual_methods_size[i]);
                      for(int k3 = 0; k3 < class_virtual_methods_size[i]; k3++)
                      {
                         virtual_methods[k3].method_idx_diff = readUnsignedLeb128(tt) + method_index;
                         method_index =  virtual_methods[k3].method_idx_diff;
                         virtual_methods[k3].access_flags = readUnsignedLeb128(tt);
                         virtual_methods[k3].code_off = readUnsignedLeb128(tt);  
                         printf("      virtual_method_idx_diff:0x%x\n",virtual_methods[k3].method_idx_diff); 
                         printf("      virtual_access_flags:0x%x\n",virtual_methods[k3].access_flags);
		         printf("      virtual_code_off:0x%x\n",virtual_methods[k3].code_off);
                         int tempCount = *((uint*)&str[virtual_methods[k3].code_off + 12]);
                         int tempAddr = virtual_methods[k3].code_off + 16;
                         printf("            tempCount:0x%x\n",tempCount);
                         printf("            tempAddr:0x%x\n",tempAddr);
                         if( virtual_methods[k3].method_idx_diff < d_header.method_ids_size){
                         printf("      methodName:%s\n",methodinfo_string[virtual_methods[k3].method_idx_diff].method_name);
                         }
                         else{
                         printf("      methodName:undefined\n");
                         }     
		         printf("      code:\n"); 
                         if(tempCount < d_header.file_size && tempCount * 2 + tempAddr < d_header.file_size){ 
                           printf("        ");  
		           for(int i = 0 ; i < tempCount; i++)
		           {
		              printf("0x%x ",*((ushort*)&str[tempAddr]));
		              tempAddr += 2;
		           }
                         }else{
                            printf("too big\n");
                         }
		         printf("\n\n");
                      }
                }
              } 
           }
              
       }
    else
    {
        printf("this file is not 'dex' format");
    }
  }

