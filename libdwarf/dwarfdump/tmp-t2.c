/*
  Copyright (C) 2000-2010 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2009-2015 David Anderson. All Rights Reserved.
  Portions Copyright 2012 SN Systems Ltd. All rights reserved.

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2.1 of the GNU Lesser General Public License
  as published by the Free Software Foundation.

  This program is distributed in the hope that it would be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

  Further, this software is distributed without any warranty that it is
  free of the rightful claim of any third person regarding infringement
  or the like.  Any license provided herein, whether implied or
  otherwise, applies only to this software file.  Patent licenses, if
  any, provided herein do not apply to combinations of this program with
  other software, or any other product whatsoever.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307,
  USA.
 
*/
#include <dwarf.h>

/*
    Entries for DWARF5 should  not be considered final
    until the DWARF5 standard is released.

    list for semantic check of tag-attr relation.

    0xffffffff is a "punctuation."  The final line of this file
    must be 0xffffffff.  The next line after each 0xffffffff
    (except the final line) is a tag.  The lines after this line
    before the next 0xffffffff are the attributes that can be given
    to the tag."

    For example,

    0xffffffff
    DW_TAG_access_declaration
    DW_AT_decl_column
    DW_AT_decl_file
    DW_AT_decl_line
    DW_AT_accessibility
    DW_AT_name
    DW_AT_sibling
    0xffffffff

    means "only DW_AT_decl_column, DW_AT_decl_file, DW_AT_decl_line,
    DW_AT_accessibility, DW_AT_name and DW_AT_sibling can be given to
    DW_TAG_access_declaration."

    Since DWARF standards are descriptive, not formally prescriptive
    (for the most part) compilers may add attributes that do not
    appear in this list. Corrections to the list are always
    appreciated.  And for extensions, the file tag_attr_ext.list
    is the right place to put such so they do not provoke
    pointless warnings.

    This file is applied to the preprocessor, thus any C comment and
    preprocessor control line is available.
*/

0xffffffff
DW_TAG_access_declaration
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_accessibility
DW_AT_description
DW_AT_name
DW_AT_sibling
0xffffffff
DW_TAG_array_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_bit_stride
DW_AT_byte_size
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_name
DW_AT_ordering
DW_AT_rank
DW_AT_sibling
DW_AT_specification
DW_AT_start_scope
DW_AT_type
DW_AT_visibility
0xffffffff
DW_TAG_atomic_type /* DWARF5 */
DW_AT_alignment
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_base_type
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_binary_scale
DW_AT_bit_offset
DW_AT_bit_size
DW_AT_byte_size
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_data_bit_offset
DW_AT_data_location
DW_AT_decimal_scale
DW_AT_decimal_sign
DW_AT_description
DW_AT_digit_count
DW_AT_encoding
DW_AT_endianity
DW_AT_name
DW_AT_picture_string
DW_AT_sibling
DW_AT_small
0xffffffff
DW_TAG_call_site /* DWARF5 */
DW_AT_call_column
DW_AT_call_file
DW_AT_call_line
DW_AT_call_origin
DW_AT_call_pc
DW_AT_call_return_pc
DW_AT_call_tail_call
DW_AT_call_target
DW_AT_call_target_clobbered
DW_AT_type
0xffffffff
DW_TAG_call_site_parameter /* DWARF5 */
DW_AT_call_data_location
DW_AT_call_data_value
DW_AT_call_parameter
DW_AT_call_value
DW_AT_location
DW_AT_name
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_catch_block
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_entry_pc
DW_AT_high_pc
DW_AT_low_pc
DW_AT_ranges
DW_AT_segment
DW_AT_sibling
0xffffffff
DW_TAG_class_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_byte_size
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_name
DW_AT_sibling
DW_AT_signature
DW_AT_specification
DW_AT_start_scope
DW_AT_visibility
0xffffffff
DW_TAG_coarray_type /* DWARF5 */
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_alignment
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_common_block
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_declaration
DW_AT_description
DW_AT_linkage_name
DW_AT_location
DW_AT_name
DW_AT_segment
DW_AT_sibling
DW_AT_visibility
0xffffffff
DW_TAG_common_inclusion
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_common_reference
DW_AT_declaration
DW_AT_sibling
DW_AT_visibility
0xffffffff
DW_TAG_compile_unit
DW_AT_addr_base
DW_AT_base_types
DW_AT_comp_dir
DW_AT_dwo_id
DW_AT_dwo_name
DW_AT_entry_pc
DW_AT_identifier_case
DW_AT_high_pc
DW_AT_language
DW_AT_low_pc
DW_AT_macro_info /* before DWARF5 */
DW_AT_macros  /* DWARF5 */
DW_AT_main_subprogram
DW_AT_name
DW_AT_producer
DW_AT_ranges
DW_AT_ranges_base
DW_AT_segment
DW_AT_stmt_list
DW_AT_str_offsets_base
DW_AT_use_UTF8
0xffffffff
DW_TAG_condition
DW_AT_decl_column
DW_AT_decl_file 
DW_AT_decl_line
DW_AT_name
DW_AT_sibling
0xffffffff
DW_TAG_const_type
DW_AT_decl_column
DW_AT_decl_file 
DW_AT_decl_line
DW_AT_alignment
DW_AT_name
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_constant
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_accessibility
DW_AT_const_value
DW_AT_declaration
DW_AT_description
DW_AT_endianity
DW_AT_external
DW_AT_linkage_name
DW_AT_name
DW_AT_sibling
DW_AT_start_scope
DW_AT_type
DW_AT_visibility
0xffffffff
DW_TAG_dwarf_procedure
DW_AT_location
0xffffffff
DW_TAG_dynamic_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_data_location
DW_AT_description
DW_AT_name
DW_AT_type
DW_AT_sibling
0xffffffff
DW_TAG_entry_point
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_address_class
DW_AT_description
DW_AT_frame_base
DW_AT_linkage_name
DW_AT_low_pc
DW_AT_name
DW_AT_return_addr
DW_AT_segment
DW_AT_sibling
DW_AT_static_link
DW_AT_type
0xffffffff
DW_TAG_enumeration_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_bit_stride
DW_AT_byte_size
DW_AT_byte_stride
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_enum_class
DW_AT_name
DW_AT_sibling
DW_AT_signature
DW_AT_specification
DW_AT_start_scope
DW_AT_type
DW_AT_visibility
0xffffffff
DW_TAG_enumerator
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_const_value
DW_AT_description
DW_AT_name
DW_AT_sibling
0xffffffff
DW_TAG_file_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_byte_size
DW_AT_data_location
DW_AT_description
DW_AT_name
DW_AT_sibling
DW_AT_start_scope
DW_AT_type
DW_AT_visibility
0xffffffff
DW_TAG_formal_parameter
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_artificial
DW_AT_const_value
DW_AT_default_value
DW_AT_description
DW_AT_endianity
DW_AT_is_optional
DW_AT_location
DW_AT_name
DW_AT_segment
DW_AT_sibling
DW_AT_type
DW_AT_variable_parameter
0xffffffff
DW_TAG_friend
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_friend
DW_AT_sibling
0xffffffff
DW_TAG_generic_subrange
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_bit_stride 
DW_AT_byte_size
DW_AT_byte_stride
DW_AT_count
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_lower_bound
DW_AT_name
DW_AT_sibling
DW_AT_threads_scaled
DW_AT_type
DW_AT_upper_bound
DW_AT_visibility
0xffffffff
DW_TAG_imported_declaration
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_accessibility
DW_AT_description
DW_AT_import
DW_AT_name
DW_AT_sibling
DW_AT_start_scope
0xffffffff
DW_TAG_imported_module
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_import
DW_AT_sibling
DW_AT_start_scope
0xffffffff
DW_TAG_imported_unit
DW_AT_import
0xffffffff
DW_TAG_inheritance
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_accessibility
DW_AT_data_member_location
DW_AT_sibling
DW_AT_type
DW_AT_virtuality
0xffffffff
DW_TAG_inlined_subroutine
DW_AT_abstract_origin
DW_AT_call_column
DW_AT_call_file
DW_AT_call_line
DW_AT_const_expr
DW_AT_entry_pc
DW_AT_high_pc
DW_AT_low_pc
DW_AT_ranges
DW_AT_return_addr
DW_AT_segment
DW_AT_sibling
DW_AT_start_scope
DW_AT_trampoline
0xffffffff
DW_TAG_interface_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_accessibility
DW_AT_alignment
DW_AT_description
DW_AT_name
DW_AT_sibling
DW_AT_start_scope
0xffffffff
DW_TAG_label
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_description
DW_AT_low_pc
DW_AT_name
DW_AT_segment
DW_AT_start_scope
DW_AT_sibling
0xffffffff
DW_TAG_lexical_block
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_description
DW_AT_entry_pc
DW_AT_high_pc
DW_AT_low_pc
DW_AT_name
DW_AT_ranges
DW_AT_segment
DW_AT_sibling
0xffffffff
DW_TAG_member
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_accessibility
DW_AT_artificial
DW_AT_bit_offset
DW_AT_bit_size
DW_AT_byte_size
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_data_bit_offset
DW_AT_data_member_location
DW_AT_declaration
DW_AT_description
DW_AT_mutable
DW_AT_name
DW_AT_sibling
DW_AT_type
DW_AT_visibility
0xffffffff
DW_TAG_module
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_accessibility
DW_AT_declaration
DW_AT_description
DW_AT_entry_pc
DW_AT_high_pc
DW_AT_low_pc
DW_AT_name
DW_AT_priority
DW_AT_ranges
DW_AT_segment
DW_AT_sibling
DW_AT_specification
DW_AT_visibility
0xffffffff
DW_TAG_namelist
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_declaration
DW_AT_name
DW_AT_sibling
DW_AT_visibility
0xffffffff
DW_TAG_namelist_item
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_namelist_item
DW_AT_sibling
0xffffffff
DW_TAG_namespace
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_description
DW_AT_export_symbols
DW_AT_extension
DW_AT_name
DW_AT_sibling
DW_AT_start_scope
0xffffffff
DW_TAG_packed_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_alignment
DW_AT_name
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_partial_unit
DW_AT_addr_base
DW_AT_base_types
DW_AT_comp_dir
DW_AT_description
DW_AT_dwo_id
DW_AT_dwo_name
DW_AT_entry_pc
DW_AT_identifier_case
DW_AT_high_pc
DW_AT_language
DW_AT_low_pc
DW_AT_macro_info
DW_AT_macros
DW_AT_main_subprogram
DW_AT_name
DW_AT_producer
DW_AT_ranges
DW_AT_ranges_base
DW_AT_segment
DW_AT_stmt_list
DW_AT_str_offsets_base
DW_AT_use_UTF8
0xffffffff
DW_TAG_pointer_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_address_class
DW_AT_alignment
DW_AT_bit_size /* DWARF4 */
DW_AT_byte_size
DW_AT_name
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_ptr_to_member_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_address_class
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_containing_type
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_name
DW_AT_sibling
DW_AT_type
DW_AT_use_location
DW_AT_visibility

0xffffffff
DW_TAG_reference_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_address_class
DW_AT_alignment
DW_AT_bit_size /* DWARF4 */
DW_AT_byte_size
DW_AT_name
DW_AT_sibling
DW_AT_type

0xffffffff
DW_TAG_restrict_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_alignment
DW_AT_sibling
DW_AT_type

0xffffffff
DW_TAG_rvalue_reference_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_address_class
/* DW_AT_allocated */
/* DW_AT_associated */
/* DW_AT_data_location */
DW_AT_name
/* DW_AT_sibling */
DW_AT_type

0xffffffff
DW_TAG_set_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size /* DWARF4 */
DW_AT_byte_size
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_name
DW_AT_start_scope
DW_AT_sibling
DW_AT_type
DW_AT_visibility

0xffffffff
DW_TAG_shared_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_allocated
DW_AT_associated
DW_AT_alignment
DW_AT_count
DW_AT_name
DW_AT_sibling
DW_AT_type

0xffffffff
DW_TAG_string_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_byte_size
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_name
DW_AT_segment
DW_AT_sibling
DW_AT_start_scope
DW_AT_string_length
DW_AT_string_length_bit_size
DW_AT_string_length_byte_size
DW_AT_visibility

0xffffffff
DW_TAG_structure_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size
DW_AT_byte_size
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_export_symbols
DW_AT_name
DW_AT_sibling
DW_AT_signature
DW_AT_specification
DW_AT_start_scope
DW_AT_visibility

0xffffffff
DW_TAG_subprogram
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_address_class
DW_AT_artificial
DW_AT_calling_convention
DW_AT_declaration
DW_AT_description
DW_AT_elemental
DW_AT_entry_pc
DW_AT_explicit
DW_AT_external
DW_AT_frame_base
DW_AT_high_pc
DW_AT_inline
DW_AT_linkage_name
DW_AT_low_pc
DW_AT_main_subprogram
DW_AT_name
DW_AT_object_pointer
DW_AT_prototyped
DW_AT_pure
DW_AT_ranges
DW_AT_recursive
DW_AT_reference
DW_AT_return_addr
DW_AT_rvalue_reference
DW_AT_segment
DW_AT_sibling
DW_AT_specification
DW_AT_start_scope
DW_AT_static_link
DW_AT_trampoline
DW_AT_type
DW_AT_visibility
DW_AT_virtuality
DW_AT_vtable_elem_location

0xffffffff
DW_TAG_subrange_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_allocated
DW_AT_associated
DW_AT_bit_stride
DW_AT_byte_size
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_byte_stride
DW_AT_count
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_lower_bound
DW_AT_name
DW_AT_sibling
DW_AT_threads_scaled
DW_AT_type
DW_AT_upper_bound
DW_AT_visibility
0xffffffff
DW_TAG_subroutine_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_address_class
DW_AT_allocated
DW_AT_associated
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_name
DW_AT_prototyped
DW_AT_rvalue_reference
DW_AT_sibling
DW_AT_start_scope
DW_AT_type
DW_AT_visibility

0xffffffff
DW_TAG_template_alias
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_allocated
DW_AT_associated
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_name
DW_AT_sibling
DW_AT_signature
DW_AT_start_scope
DW_AT_type
DW_AT_visibility


0xffffffff
DW_TAG_template_type_parameter
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_default_value
DW_AT_description
DW_AT_name
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_template_value_parameter
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_const_value
DW_AT_default_value
DW_AT_description
DW_AT_location
DW_AT_name
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_thrown_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_data_location
DW_AT_sibling
DW_AT_type
0xffffffff
DW_TAG_try_block
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_entry_pc
DW_AT_high_pc
DW_AT_low_pc
DW_AT_ranges
DW_AT_segment
DW_AT_sibling
0xffffffff
DW_TAG_typedef
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_name
DW_AT_sibling
DW_AT_start_scope
DW_AT_type
DW_AT_visibility

0xffffffff
DW_TAG_type_unit
DW_AT_language
DW_AT_stmt_list
DW_AT_str_offsets_base
DW_AT_use_UTF8

0xffffffff
DW_TAG_union_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_alignment
DW_AT_allocated
DW_AT_associated
DW_AT_bit_size /* Allowed in DWARF4 */
DW_AT_byte_size
DW_AT_data_location
DW_AT_declaration
DW_AT_description
DW_AT_export_symbols
DW_AT_name
DW_AT_sibling
DW_AT_signature
DW_AT_specification
DW_AT_start_scope
DW_AT_visibility
0xffffffff
DW_TAG_unspecified_parameters
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_artificial
DW_AT_sibling
0xffffffff
DW_TAG_unspecified_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_description
DW_AT_name
/* DW_AT_sibling ? */

0xffffffff
DW_TAG_variable
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_alignment
DW_AT_artificial
DW_AT_byte_size
DW_AT_bit_size
DW_AT_const_expr
DW_AT_const_value
DW_AT_declaration
DW_AT_description
DW_AT_endianity
DW_AT_external
DW_AT_linkage_name
DW_AT_location
DW_AT_name
DW_AT_segment
DW_AT_sibling
DW_AT_specification
DW_AT_start_scope
DW_AT_type
DW_AT_visibility

0xffffffff
DW_TAG_variant
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_accessibility
DW_AT_abstract_origin
DW_AT_declaration
DW_AT_discr_list
DW_AT_discr_value
DW_AT_sibling

0xffffffff
DW_TAG_variant_part
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
DW_AT_abstract_origin
DW_AT_accessibility
DW_AT_declaration
DW_AT_discr
DW_AT_sibling
DW_AT_type

0xffffffff
DW_TAG_volatile_type
DW_AT_decl_column
DW_AT_decl_file
DW_AT_decl_line
/* DW_AT_allocated ? */
/* DW_AT_associated ? */
/* DW_AT_data_location ? */
DW_AT_name
DW_AT_sibling
DW_AT_type

0xffffffff
DW_TAG_with_stmt
DW_AT_accessibility
DW_AT_address_class
DW_AT_declaration
DW_AT_entry_pc
DW_AT_high_pc
DW_AT_location
DW_AT_low_pc
DW_AT_ranges
DW_AT_segment
DW_AT_sibling
DW_AT_type
DW_AT_visibility
0xffffffff
