
#-------------------------------------------------------------------------------
# elftools example: dwarf_die_tree.py
#
# In the .debug_info section, Dwarf Information Entries (DIEs) form a tree.
# pyelftools provides easy access to this tree, as demonstrated here.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import print_function
import sys
import collections
from recordtype import recordtype
# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.elf.elffile import ELFFile

#Data_type = collections.namedtuple('Data_type', 'name value')
Data_type = recordtype('Data_type', 'name value')
Var_data = collections.namedtuple('Var_data', 'name type location')

def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.
            print('  Found a compile unit at offset %s, length %s' % (
                CU.cu_offset, CU['unit_length']))

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()
            print('    Top DIE with tag=%s' % top_DIE.tag)

            # We're interested in the filename...
            print('    name=%s' % top_DIE.get_full_path())

        #for DIE in CU.iterDIE():
            # Display DIEs recursively starting with top_DIE
            dict_data_type = dict()
            
            die_info_rec(top_DIE, dict_data_type)
            
            dict_struct_info = dict()
            get_struct_info(top_DIE, dict_struct_info)
            
            for dataoffset, typevalue in dict_data_type.items():
                
                final_name = typevalue.name
                origval = typevalue.value
                while origval != -1:
                
                    if origval in dict_data_type:
                        val = dict_data_type[origval].value
                        final_name = dict_data_type[origval].name + ' ' + final_name
                        origval = val

                dict_data_type[dataoffset].name = final_name
                #print(str(dataoffset) + " : "+dict_data_type[dataoffset].name + " : " + str(dict_data_type[dataoffset].value))

            #print(dict_data_type)
            dict_var = dict()
            list_var = []
            dict_var, list_var = get_list_func(top_DIE, dict_var, list_var, dict_data_type, dict_struct_info)
            print()
            print(dict_var)
            print()
            for ele in list_var:
                print(ele)

def get_struct_info(die, dict_struct_info, is_struct_child = False,struct_parent_offset = -1):
    
    child_offset = -1
    if die.tag == 'DW_TAG_structure_type':
        is_struct_child = True
        for key,attrvalue in die.attributes.items():
            if key == 'DW_AT_name':
                struct_parent_offset = attrvalue.offset - 1
                break
        
    elif is_struct_child == True and die.tag == 'DW_TAG_member':
        for key,attrvalue in die.attributes.items():
            if key == 'DW_AT_type':
                child_type = attrvalue.value
                temp_struct_memlist = list()
                
                if struct_parent_offset in dict_struct_info:
                    temp_struct_memlist = dict_struct_info[struct_parent_offset]

                temp_struct_memlist.append(child_type)
                dict_struct_info[struct_parent_offset] = temp_struct_memlist

                break

    else:
        is_struct_child = False
        struct_parent_offset = -1

    for child in die.iter_children():
        get_struct_info(child, dict_struct_info, is_struct_child, struct_parent_offset)




def get_list_func(die, dict_var, list_var, dict_data_type, dict_struct_info):

    for child in die.iter_children():
        if child.tag == 'DW_TAG_subprogram':

            for key,attrvalue in child.attributes.items():
                if key == 'DW_AT_name' and attrvalue.value != 'main':
                    for kid in child.iter_children():
                        dict_var,list_var = get_var_info(kid, dict_var,list_var, dict_data_type, dict_struct_info)

    return dict_var,list_var

def get_var_info(die, dict_var, list_var, dict_data_type, dict_struct_info):
    var_name = ''
    var_loc = ''
    var_type = ''
    var_offset = -1
    for key, attrvalue in die.attributes.items():
        if key == 'DW_AT_name':
            var_name = attrvalue.value
            
        elif key == 'DW_AT_type':
            if attrvalue.value in dict_data_type:
                var_offset = attrvalue.value
                var_type = dict_data_type[attrvalue.value].name
                if var_type in dict_var:
                    dict_var[var_type] = dict_var[var_type] + 1
                else:
                    dict_var[var_type] = 1

                

                

        elif key == 'DW_AT_location':
            loc_list = attrvalue.value
            hex_loc = ''
            for dec_loc in loc_list:
                hex_loc += hex(dec_loc)[2:]
            var_loc = '0x' + hex_loc

        elif var_offset == -1:
            var_offset = attrvalue.offset - 1

    #if it is a struct enter all its members
    if 'struct' in var_type:
        var_offset = get_offset(var_offset,dict_data_type)
        put_struct_mem(var_offset, dict_var, dict_data_type, dict_struct_info)
    
    if len(var_name) > 0: 
        list_var.append(Var_data(name=var_name, type=var_type, location=var_loc))

    return dict_var,list_var

def get_offset(offset,dict_data_type):
    temp = dict_data_type[offset].value
    curroffset = temp
    while temp != -1:
        if temp in dict_data_type:
            curroffset = temp
            temp = dict_data_type[temp].value
    return curroffset


def put_struct_mem(offset, dict_var,dict_data_type,dict_struct_info):
    if offset in dict_struct_info:
        struct_memlist = dict_struct_info[offset]

        for ele in struct_memlist:
            if ele in dict_data_type:
                var_type = dict_data_type[ele].name
                if var_type in dict_var:
                    dict_var[var_type] = dict_var[var_type] + 1
                else:
                    dict_var[var_type] = 1

def die_info_rec(die, dict_data_type):
    """ A recursive function for showing information about a DIE and its
        children.
    """
    data_type_offset = -1
    data_type_name = ''
    data_type_val = -1
    #print(indent_level + 'DIE tag=%s' % die.tag)
    if die.tag == 'DW_TAG_base_type':
        
        for key, attrvalue in die.attributes.items():
            if key == 'DW_AT_byte_size':
                data_type_offset = attrvalue.offset - 1
            if key == 'DW_AT_name':
                data_type_name = attrvalue.value
            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1
                
        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=-1)

    
    #print('Yes') #DW_TAG_typedef ,DW_TAG_pointer_type, DW_TAG_const_type, DW_TAG_structure_type, DW_TAG_member
    elif die.tag == 'DW_TAG_pointer_type':
        for key, attrvalue in die.attributes.items():
        
            if key == 'DW_AT_type':
                data_type_val = attrvalue.value
            
            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1
        
        data_type_name = 'pointer'
        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)
    
    elif die.tag == 'DW_TAG_structure_type':
        for key, attrvalue in die.attributes.items():
            # if data_type_offset > attrvalue.offset:
            #     data_type_offset = attrvalue.offset

            if key == 'DW_AT_name':
                data_type_offset = attrvalue.offset - 1
                data_type_name = "struct"

            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1
        
        
        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=-1)

    elif die.tag == 'DW_TAG_typedef':
        for key, attrvalue in die.attributes.items():
            # if data_type_offset > attrvalue.offset:
            #     data_type_offset = attrvalue.offset

            if key == 'DW_AT_name':
                data_type_offset = attrvalue.offset - 1
                data_type_name = ""

            if key == 'DW_AT_type':
                data_type_val = attrvalue.value
        
            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1

        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)

    elif die.tag == 'DW_TAG_member':
        
        for key, attrvalue in die.attributes.items():
            if key == 'DW_AT_name':
                data_type_offset = attrvalue.offset - 1
                data_type_name = attrvalue.value

            if key == 'DW_AT_type':
                data_type_val = attrvalue.value

            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1
        #print(str(data_type_offset) + " : " + data_type_name + " : " + str(data_type_val) + str(len(dict_data_type)))        
        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)
        #print(str(len(dict_data_type)))

    elif die.tag == 'DW_TAG_formal_parameter':
        
        for key, attrvalue in die.attributes.items():
            if key == 'DW_AT_name':
                data_type_offset = attrvalue.offset - 1
                data_type_name = attrvalue.value

            if key == 'DW_AT_type':
                data_type_val = attrvalue.value

            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1
        #print(str(data_type_offset) + " : " + data_type_name + " : " + str(data_type_val) + str(len(dict_data_type)))        
        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)

    elif die.tag == 'DW_TAG_typedef':
        for key, attrvalue in die.attributes.items():
            # if data_type_offset > attrvalue.offset:
            #     data_type_offset = attrvalue.offset

            if key == 'DW_AT_name':
                data_type_offset = attrvalue.offset - 1
                data_type_name = "typedef"

            if key == 'DW_AT_type':
                data_type_val = attrvalue.value
        
            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1

        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)

    elif die.tag == 'DW_TAG_const_type':
        for key, attrvalue in die.attributes.items():
            
            data_type_offset = attrvalue.offset - 1
            data_type_name = "const"
            data_type_val = attrvalue.value
                
        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)

    elif die.tag == 'DW_TAG_array_type':
        for key, attrvalue in die.attributes.items():

            if key == 'DW_AT_type':
                data_type_val = attrvalue.value
                data_type_offset = attrvalue.offset - 1
                data_type_name = "[]"

            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1
                
        dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)

    elif die.tag == 'DW_TAG_subrange_type':
        for key, attrvalue in die.attributes.items():

            if key == 'DW_AT_type':
                data_type_val = attrvalue.value
                data_type_offset = attrvalue.offset - 1
                data_type_name = "subrange"

            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1
        if data_type_offset != -1:         
            dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)

    elif die.tag == 'DW_TAG_subroutine_type':
        for key, attrvalue in die.attributes.items():

            if key == 'DW_AT_type':
                data_type_val = attrvalue.value
                data_type_offset = attrvalue.offset - 1
                

            if data_type_offset == -1:
                data_type_offset = attrvalue.offset - 1
        
        data_type_name = "function"
        if data_type_offset != -1:         
            dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)

    elif die.tag in {'DW_TAG_class_type', 'DW_TAG_enumeration_type','DW_TAG_enumerator', 'DW_TAG_reference_type','DW_TAG_string_type','DW_TAG_union_type','DW_TAG_ptr_to_member_type','DW_TAG_set_type','DW_TAG_constant','DW_TAG_file_type','DW_TAG_namelist','DW_TAG_packed_type','DW_TAG_volatile_type','DW_TAG_restrict_type','DW_TAG_interface_type','DW_TAG_unspecified_type','DW_TAG_shared_type'}:
        for key, attrvalue in die.attributes.items():
            
            data_type_offset = attrvalue.offset - 1
            tempstr = (die.tag).split('_',1)
            data_type_name = tempstr[2]
            data_type_val = -1
                
        if data_type_offset != -1:                   
            dict_data_type[data_type_offset] = Data_type(name=data_type_name, value=data_type_val)

    #child_indent = indent_level + '  '
    for child in die.iter_children():
        die_info_rec(child, dict_data_type)


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            process_file(filename)
