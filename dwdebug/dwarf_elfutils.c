#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "dwdebug.h"

#include "memory-access.h"

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>


/**
 ** Most of the src in this file is slightly-tweaked stuff from
 ** elfutils, especially readelf.c.  May as well just take all their
 ** stuff -- plus it is more relocation-ready!
 **/

/*
 * This is taken directly from elfutils/src/readelf.c, tweaked into
 * "better" C, and hooked so that we can "detect" end of prologues.
 */
int get_lines(struct debugfile *debugfile,Dwarf_Off offset,size_t address_size) {
    unsigned char *linestartp = (unsigned char *)&debugfile->linetab[offset];
    unsigned char *lineendp = (unsigned char *)debugfile->linetab + debugfile->linetablen;
    unsigned char *linep = linestartp;
    const unsigned char *clinep;
    unsigned char *endp;
    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;
    size_t start_offset;
    Dwarf_Word unit_length;
    unsigned int length;
    uint_fast16_t version;
    Dwarf_Word header_length;
    uint_fast8_t minimum_instr_len;
    uint_fast8_t max_ops_per_instr;
    uint_fast8_t default_is_stmt;
    int_fast8_t line_base;
    uint_fast8_t line_range;
    uint_fast8_t opcode_base;
    uint8_t *standard_opcode_lengths;
    unsigned int u128;
    int s128;
    Dwarf_Word address;
    unsigned int op_index;
    size_t line;
    uint_fast8_t is_stmt;
    unsigned int opcode;
    int line_increment;
    int i;
    struct symbol *symbol = NULL;
    struct symbol *candidate_symbol = NULL;
    bool prologue_end = false;
    bool epilogue_begin = false;

    /* We only recognize addresses for symbols in this table, so don't
     * process if there are no addresses!  (unlikey)
     */
    if (g_hash_table_size(debugfile->addresses) == 0) 
	return 0;

    vdebug(5,LOG_D_DWARF,"processing lines at offset 0x%lx!\n",offset);

    while (linep < lineendp) {
	start_offset = linep - linestartp;
	unit_length = read_4ubyte_unaligned_inc(obo,linep);
	length = 4;

	if (unlikely (unit_length == 0xffffffff)) {
	    if (unlikely (linep + 8 > lineendp)) 
		goto invalid_data_out;

	    unit_length = read_8ubyte_unaligned_inc(obo,linep);
	    length = 8;
	}

	/* Check whether we have enough room in the section.  */
	if (unit_length < 2 + length + 5 * 1
	    || unlikely (linep + unit_length > lineendp))
	    goto invalid_data_out;

	lineendp = linep + unit_length;

	/* The next element of the header is the version identifier.  */
	version = read_2ubyte_unaligned_inc(obo,linep);

	/* Next comes the header length.  */
	if (length == 4)
	    header_length = read_4ubyte_unaligned_inc(obo,linep);
	else
	    header_length = read_8ubyte_unaligned_inc(obo,linep);

	/* Next the minimum instruction length.  */
	minimum_instr_len = *linep++;

	/* Next the maximum operations per instruction, in version 4 format.  */
	max_ops_per_instr = version < 4 ? 1 : *linep++;

	/* Then the flag determining the default value of the is_stmt
	   register.  */
	default_is_stmt = *linep++;

	/* Now the line base.  */
	line_base = *((int_fast8_t *)linep);
	++linep;

	/* And the line range.  */
	line_range = *(linep++);

	/* The opcode base.  */
	opcode_base = *(linep++);

	if (unlikely (linep + opcode_base - 1 >= lineendp))
	    goto invalid_unit_out;

	standard_opcode_lengths = linep - 1;

	linep += opcode_base - 1;
	if (unlikely(linep >= lineendp))
	    goto invalid_unit_out;

	while (*linep != 0) {
	    endp = memchr(linep,'\0',lineendp - linep);
	    if (unlikely(endp == NULL))
		goto invalid_unit_out;

	    linep = endp + 1;
	}
	/* Skip the final NUL byte.  */
	++linep;

	if (unlikely(linep >= lineendp))
	    goto invalid_unit_out;

	while (*linep != 0) {
	    /* First comes the file name.  */
	    endp = memchr(linep,'\0',lineendp - linep);
	    if (unlikely(endp == NULL))
		goto invalid_unit_out;
	    linep = endp + 1;

	    /* Then the index.  */
	    clinep = (const unsigned char *)linep;
	    get_uleb128(u128,clinep);

	    /* Next comes the modification time.  */
	    get_uleb128(u128,clinep);

	    /* Finally the length of the file.  */
	    get_uleb128(u128,clinep);

	    linep = (unsigned char *)clinep;
	}
	/* Skip the final NUL byte.  */
	++linep;

	address = 0;
	op_index = 0;
	line = 1;
	is_stmt = default_is_stmt;
	prologue_end = false;
	epilogue_begin = false;

	inline void advance_pc(unsigned int op_advance) {
	    address += op_advance;
	    op_index = (op_index + op_advance) % max_ops_per_instr;
	}

	while (linep < lineendp) {
	    /* Read the opcode.  */
	    opcode = *(unsigned char *)linep++;

	    /* Is this a special opcode?  */
	    if (likely(opcode >= opcode_base)) {
		/* Yes.  Handling this is quite easy since the opcode value
		   is computed with

		   opcode = (desired line increment - line_base)
		             + (line_range * address advance) + opcode_base
		*/
		line_increment = (line_base
				  + (opcode - opcode_base) % line_range);

		/* Perform the increments.  */
		line += line_increment;
		advance_pc((opcode - opcode_base) / line_range);

		/*
		 * If the epilogue_begin register is set, try to do it.
		 */
		if (epilogue_begin && candidate_symbol) {
		    /* Use it if the address is in the function range. */
		    if (symbol_contains_addr(candidate_symbol,address)) {
			candidate_symbol->s.ii.d.f.epilogue_begin =	\
			    (ADDR)address;
			vdebug(3,LOG_D_DWARF,
			       "set_epilogue_begin: %s is 0x%"PRIxADDR"\n",
			       candidate_symbol->name,(ADDR)address);
		    }
		    else {
			vdebug(5,LOG_D_DWARF,
			       "set_epilogue_begin: address 0x%"PRIxADDR" not in %s\n",
			       (ADDR)address,candidate_symbol->name);
		    }
		}

		/*
		 * If the prologue_end register is set, try to use that
		 * before doing autodetection.
		 */
		if (prologue_end && candidate_symbol) {
		    /* Use it if the address is in the function range. */
		    if (symbol_contains_addr(candidate_symbol,address)) {
			candidate_symbol->s.ii.d.f.prologue_end = (ADDR)address;
			vdebug(3,LOG_D_DWARF,
			       "set_prologue_end: %s is 0x%"PRIxADDR"\n",
			       candidate_symbol->name,(ADDR)address);

			/* Unset auto detected flag; we have one for
			   sure. */
			candidate_symbol->s.ii.d.f.prologue_guessed = 0;

			/* Unset symbol so we don't try to use "auto"
			   detection. */
			symbol = NULL;
		    }
		    else {
			vdebug(5,LOG_D_DWARF,
			       "set_prologue_end: address 0x%"PRIxADDR" not in %s\n",
			       (ADDR)address,candidate_symbol->name);
		    }
		}

		/* Clear prologue_end and epilogue_begin registers as
		   per the spec. */
		prologue_end = false;
		epilogue_begin = false;

		/*
		 * Try to find a symbol at this address; if we find one,
		 * and it is a function, set its prologue_end value!
		 */
		if (symbol) {
		    /* If the current address is not in s, assume we're
		     * done with it!
		     *
		     * XXX: is this right?
		     */
		    if (symbol_contains_addr(symbol,address)) {
			symbol->s.ii.d.f.prologue_end = (ADDR)address;
			vdebug(3,LOG_D_DWARF,
			       "assuming prologue_end of %s is 0x%"PRIxADDR"\n",
			       symbol->name,(ADDR)address);

			/* Set auto detected flag; we're just guessing! */
			symbol->s.ii.d.f.prologue_guessed = 1;
		    }
		    else {
			vdebug(5,LOG_D_DWARF,
			       "address 0x%"PRIxADDR" not in %s\n",
			       (ADDR)address,symbol->name);
		    }

		    /*
		     * We only assume the first address after seeing the
		     * function's lowest address is the end of prologue.
		     */
		    symbol = NULL;
		}

		if (!symbol) {
		    symbol = debugfile_lookup_addr(debugfile,(ADDR)address);
		    if (symbol) {
			vdebug(3,LOG_D_DWARF,
			       "found candidate prologue function %s at 0x%"PRIxADDR"\n",
			       symbol->name,(ADDR)address);
			candidate_symbol = symbol;
		    }
		    else 
			vdebug(5,LOG_D_DWARF,
			       "did not find function at 0x%"PRIxADDR"\n",
			       (ADDR)address);
		}
	    }
	    else if (opcode == 0) {
		/* This an extended opcode.  */
		if (unlikely(linep + 2 > lineendp))
		    goto invalid_unit_out;

		/* The length.  */
		length = *(unsigned char *)linep++;

		if (unlikely(linep + length > lineendp))
		    goto invalid_unit_out;

		/* The sub-opcode.  */
		opcode = *(unsigned char *)linep++;

		switch (opcode) {
		case DW_LNE_end_sequence:
		    /* Reset the registers we care about.  */
		    address = 0;
		    op_index = 0;
		    line = 1;
		    is_stmt = default_is_stmt;
		    break;
		case DW_LNE_set_address:
		    op_index = 0;
		    if (address_size == 4)
			address = read_4ubyte_unaligned_inc(obo,linep);
		    else
			address = read_8ubyte_unaligned_inc(obo,linep);

		    vwarn("ext op addr 0x%"PRIxADDR"\n",address);

		    if (!symbol) {
			symbol = debugfile_lookup_addr(debugfile,(ADDR)address);
			if (symbol) {
			    vdebug(3,LOG_D_DWARF,
				   "found candidate prologue function %s at 0x%"PRIxADDR"\n",
				   symbol->name,(ADDR)address);
			    candidate_symbol = symbol;
			}
		    }

		    break;
		case DW_LNE_define_file:;
		    endp = memchr(linep,'\0',lineendp - linep);
		    if (unlikely(endp == NULL))
			goto invalid_unit_out;
		    linep = endp + 1;

		    clinep = (const unsigned char *)linep;
		    /* unsigned int diridx; */
		    get_uleb128(u128,clinep);
		    /* Dwarf_Word mtime; */
		    get_uleb128(u128,clinep);
		    /* Dwarf_Word filelength; */
		    get_uleb128(u128,clinep);
		    linep = (unsigned char *)clinep;

		    break;
		case DW_LNE_set_discriminator:
		    /* Takes one ULEB128 parameter, the discriminator.  */
		    if (unlikely(standard_opcode_lengths[opcode] != 1))
			goto invalid_unit_out;

		    clinep = (const unsigned char *)linep;
		    get_uleb128(u128,clinep);
		    linep = (unsigned char *)clinep;
		    break;
		default:
		    /* Unknown, ignore it.  */
		    vwarn("unknown opcode\n");
		    linep += length - 1;
		    break;
		}
	    }
	    else if (opcode <= DW_LNS_set_isa) {
		/* This is a known standard opcode.  */
		switch (opcode) {
		case DW_LNS_copy:
		    /* Takes no argument.  */
		    /* Clear prologue_end and epilogue_begin registers as
		       per the spec. */
		    prologue_end = false;
		    epilogue_begin = false;
		    break;
		case DW_LNS_advance_pc:
		    /* Takes one uleb128 parameter which is added to the
		       address.  */
		    clinep = (const unsigned char *)linep;
		    get_uleb128(u128,clinep);
		    linep = (unsigned char *)clinep;
		    advance_pc(u128);
		    break;
		case DW_LNS_advance_line:
		    /* Takes one sleb128 parameter which is added to the
		       line.  */
		    clinep = (const unsigned char *)linep;
		    get_sleb128(s128,clinep);
		    linep = (unsigned char *)clinep;
		    line += s128;
		    break;
		case DW_LNS_set_file:
		    /* Takes one uleb128 parameter which is stored in file.  */
		    clinep = (const unsigned char *)linep;
		    get_uleb128(u128,clinep);
		    linep = (unsigned char *)clinep;
		    break;
		case DW_LNS_set_column:
		    /* Takes one uleb128 parameter which is stored in column.  */
		    if (unlikely(standard_opcode_lengths[opcode] != 1))
			goto invalid_unit_out;
		    clinep = (const unsigned char *)linep;
		    get_uleb128(u128,clinep);
		    linep = (unsigned char *)clinep;
		    break;
		case DW_LNS_negate_stmt:
		    /* Takes no argument.  */
		    is_stmt = 1 - is_stmt;
		    break;
		case DW_LNS_set_basic_block:
		    /* Takes no argument.  */
		    break;
		case DW_LNS_const_add_pc:
		    /* Takes no argument.  */
		    advance_pc((255 - opcode_base) / line_range);
		    break;
		case DW_LNS_fixed_advance_pc:
		    /* Takes one 16 bit parameter which is added to the
		       address.  */
		    if (unlikely(standard_opcode_lengths[opcode] != 1))
			goto invalid_unit_out;
		    u128 = read_2ubyte_unaligned_inc(obo,linep);
		    address += u128;
		    op_index = 0;
		    break;
		case DW_LNS_set_prologue_end:
		    /* Takes no argument.  */
		    prologue_end = true;
		    break;
		case DW_LNS_set_epilogue_begin:
		    /* Takes no argument.  */
		    epilogue_begin = true;
		    break;
		case DW_LNS_set_isa:
		    /* Takes one uleb128 parameter which is stored in isa.  */
		    if (unlikely(standard_opcode_lengths[opcode] != 1))
			goto invalid_unit_out;
		    clinep = (const unsigned char *)linep;
		    get_uleb128(u128,clinep);
		    linep = (unsigned char *)clinep;
		    break;
		}
	    }
	    else {
		/* This is a new opcode the generator but not we know about.
		   Read the parameters associated with it but then discard
		   everything.  Read all the parameters for this opcode.  */
		vwarn(" unknown opcode with %" PRIu8 " parameters:",
		      standard_opcode_lengths[opcode]);
		for (i = standard_opcode_lengths[opcode]; i > 0; --i) {
		    clinep = (const unsigned char *)linep;
		    get_uleb128(u128,clinep);
		    linep = (unsigned char *)clinep;
		    if (i != standard_opcode_lengths[opcode])
			vwarnc(",");
		    vwarnc(" %u",u128);
		}
		vwarnc("\n");

		/* Next round, ignore this opcode.  */
		continue;
	    }
	}
    }

    return 0;

 invalid_unit_out:
    verror("invalid data at offset %tu\n",linep - linestartp);
    return -1;

 invalid_data_out:
    verror("invalid line data (overrun)!\n");
    return -1;
}

/**
 ** Convenience string functions, straight out of elfutils/readelf.c !
 **/
const char *
dwarf_tag_string (unsigned int tag)
{
  static const char *const known_tags[]  =
    {
      [DW_TAG_array_type] = "array_type",
      [DW_TAG_class_type] = "class_type",
      [DW_TAG_entry_point] = "entry_point",
      [DW_TAG_enumeration_type] = "enumeration_type",
      [DW_TAG_formal_parameter] = "formal_parameter",
      [DW_TAG_imported_declaration] = "imported_declaration",
      [DW_TAG_label] = "label",
      [DW_TAG_lexical_block] = "lexical_block",
      [DW_TAG_member] = "member",
      [DW_TAG_pointer_type] = "pointer_type",
      [DW_TAG_reference_type] = "reference_type",
      [DW_TAG_compile_unit] = "compile_unit",
      [DW_TAG_string_type] = "string_type",
      [DW_TAG_structure_type] = "structure_type",
      [DW_TAG_subroutine_type] = "subroutine_type",
      [DW_TAG_typedef] = "typedef",
      [DW_TAG_union_type] = "union_type",
      [DW_TAG_unspecified_parameters] = "unspecified_parameters",
      [DW_TAG_variant] = "variant",
      [DW_TAG_common_block] = "common_block",
      [DW_TAG_common_inclusion] = "common_inclusion",
      [DW_TAG_inheritance] = "inheritance",
      [DW_TAG_inlined_subroutine] = "inlined_subroutine",
      [DW_TAG_module] = "module",
      [DW_TAG_ptr_to_member_type] = "ptr_to_member_type",
      [DW_TAG_set_type] = "set_type",
      [DW_TAG_subrange_type] = "subrange_type",
      [DW_TAG_with_stmt] = "with_stmt",
      [DW_TAG_access_declaration] = "access_declaration",
      [DW_TAG_base_type] = "base_type",
      [DW_TAG_catch_block] = "catch_block",
      [DW_TAG_const_type] = "const_type",
      [DW_TAG_constant] = "constant",
      [DW_TAG_enumerator] = "enumerator",
      [DW_TAG_file_type] = "file_type",
      [DW_TAG_friend] = "friend",
      [DW_TAG_namelist] = "namelist",
      [DW_TAG_namelist_item] = "namelist_item",
      [DW_TAG_packed_type] = "packed_type",
      [DW_TAG_subprogram] = "subprogram",
      [DW_TAG_template_type_parameter] = "template_type_parameter",
      [DW_TAG_template_value_parameter] = "template_value_parameter",
      [DW_TAG_thrown_type] = "thrown_type",
      [DW_TAG_try_block] = "try_block",
      [DW_TAG_variant_part] = "variant_part",
      [DW_TAG_variable] = "variable",
      [DW_TAG_volatile_type] = "volatile_type",
      [DW_TAG_dwarf_procedure] = "dwarf_procedure",
      [DW_TAG_restrict_type] = "restrict_type",
      [DW_TAG_interface_type] = "interface_type",
      [DW_TAG_namespace] = "namespace",
      [DW_TAG_imported_module] = "imported_module",
      [DW_TAG_unspecified_type] = "unspecified_type",
      [DW_TAG_partial_unit] = "partial_unit",
      [DW_TAG_imported_unit] = "imported_unit",
      [DW_TAG_mutable_type] = "mutable_type",
      [DW_TAG_condition] = "condition",
      [DW_TAG_shared_type] = "shared_type",
#if HAVE_ELFUTILS_VERSION >= 152
      [DW_TAG_type_unit] = "type_unit",
      [DW_TAG_rvalue_reference_type] = "rvalue_reference_type",
      [DW_TAG_template_alias] = "template_alias",
#endif
    };
  const unsigned int nknown_tags = (sizeof (known_tags)
				    / sizeof (known_tags[0]));
  static char buf[40];
  const char *result = NULL;

  if (likely (tag < nknown_tags))
    result = known_tags[tag];

  if (unlikely (result == NULL))
    /* There are a few known extensions.  */
    switch (tag)
      {
      case DW_TAG_MIPS_loop:
	result = "MIPS_loop";
	break;

      case DW_TAG_format_label:
	result = "format_label";
	break;

      case DW_TAG_function_template:
	result = "function_template";
	break;

      case DW_TAG_class_template:
	result = "class_template";
	break;

#if HAVE_ELFUTILS_VERSION >= 152
      case DW_TAG_GNU_BINCL:
	result = "GNU_BINCL";
	break;

      case DW_TAG_GNU_EINCL:
	result = "GNU_EINCL";
	break;

      case DW_TAG_GNU_template_template_param:
	result = "GNU_template_template_param";
	break;

      case DW_TAG_GNU_template_parameter_pack:
	result = "GNU_template_parameter_pack";
	break;

      case DW_TAG_GNU_formal_parameter_pack:
	result = "GNU_formal_parameter_pack";
	break;
#endif

      default:
	if (tag < DW_TAG_lo_user)
	  snprintf (buf, sizeof buf, "unknown tag %hx", tag);
	else
	  snprintf (buf, sizeof buf, "unknown user tag %hx", tag);
	result = buf;
	break;
      }

  return result;
}


const char *
dwarf_attr_string (unsigned int attrnum)
{
  static const char *const known_attrs[] =
    {
      [DW_AT_sibling] = "sibling",
      [DW_AT_location] = "location",
      [DW_AT_name] = "name",
      [DW_AT_ordering] = "ordering",
      [DW_AT_subscr_data] = "subscr_data",
      [DW_AT_byte_size] = "byte_size",
      [DW_AT_bit_offset] = "bit_offset",
      [DW_AT_bit_size] = "bit_size",
      [DW_AT_element_list] = "element_list",
      [DW_AT_stmt_list] = "stmt_list",
      [DW_AT_low_pc] = "low_pc",
      [DW_AT_high_pc] = "high_pc",
      [DW_AT_language] = "language",
      [DW_AT_member] = "member",
      [DW_AT_discr] = "discr",
      [DW_AT_discr_value] = "discr_value",
      [DW_AT_visibility] = "visibility",
      [DW_AT_import] = "import",
      [DW_AT_string_length] = "string_length",
      [DW_AT_common_reference] = "common_reference",
      [DW_AT_comp_dir] = "comp_dir",
      [DW_AT_const_value] = "const_value",
      [DW_AT_containing_type] = "containing_type",
      [DW_AT_default_value] = "default_value",
      [DW_AT_inline] = "inline",
      [DW_AT_is_optional] = "is_optional",
      [DW_AT_lower_bound] = "lower_bound",
      [DW_AT_producer] = "producer",
      [DW_AT_prototyped] = "prototyped",
      [DW_AT_return_addr] = "return_addr",
      [DW_AT_start_scope] = "start_scope",
      [DW_AT_bit_stride] = "bit_stride",
      [DW_AT_upper_bound] = "upper_bound",
      [DW_AT_abstract_origin] = "abstract_origin",
      [DW_AT_accessibility] = "accessibility",
      [DW_AT_address_class] = "address_class",
      [DW_AT_artificial] = "artificial",
      [DW_AT_base_types] = "base_types",
      [DW_AT_calling_convention] = "calling_convention",
      [DW_AT_count] = "count",
      [DW_AT_data_member_location] = "data_member_location",
      [DW_AT_decl_column] = "decl_column",
      [DW_AT_decl_file] = "decl_file",
      [DW_AT_decl_line] = "decl_line",
      [DW_AT_declaration] = "declaration",
      [DW_AT_discr_list] = "discr_list",
      [DW_AT_encoding] = "encoding",
      [DW_AT_external] = "external",
      [DW_AT_frame_base] = "frame_base",
      [DW_AT_friend] = "friend",
      [DW_AT_identifier_case] = "identifier_case",
      [DW_AT_macro_info] = "macro_info",
      [DW_AT_namelist_item] = "namelist_item",
      [DW_AT_priority] = "priority",
      [DW_AT_segment] = "segment",
      [DW_AT_specification] = "specification",
      [DW_AT_static_link] = "static_link",
      [DW_AT_type] = "type",
      [DW_AT_use_location] = "use_location",
      [DW_AT_variable_parameter] = "variable_parameter",
      [DW_AT_virtuality] = "virtuality",
      [DW_AT_vtable_elem_location] = "vtable_elem_location",
      [DW_AT_allocated] = "allocated",
      [DW_AT_associated] = "associated",
      [DW_AT_data_location] = "data_location",
      [DW_AT_byte_stride] = "byte_stride",
      [DW_AT_entry_pc] = "entry_pc",
      [DW_AT_use_UTF8] = "use_UTF8",
      [DW_AT_extension] = "extension",
      [DW_AT_ranges] = "ranges",
      [DW_AT_trampoline] = "trampoline",
      [DW_AT_call_column] = "call_column",
      [DW_AT_call_file] = "call_file",
      [DW_AT_call_line] = "call_line",
      [DW_AT_description] = "description",
      [DW_AT_binary_scale] = "binary_scale",
      [DW_AT_decimal_scale] = "decimal_scale",
      [DW_AT_small] = "small",
      [DW_AT_decimal_sign] = "decimal_sign",
      [DW_AT_digit_count] = "digit_count",
      [DW_AT_picture_string] = "picture_string",
      [DW_AT_mutable] = "mutable",
      [DW_AT_threads_scaled] = "threads_scaled",
      [DW_AT_explicit] = "explicit",
      [DW_AT_object_pointer] = "object_pointer",
      [DW_AT_endianity] = "endianity",
      [DW_AT_elemental] = "elemental",
      [DW_AT_pure] = "pure",
      [DW_AT_recursive] = "recursive",
#if HAVE_ELFUTILS_VERSION >= 152
      [DW_AT_signature] = "signature",
      [DW_AT_main_subprogram] = "main_subprogram",
      [DW_AT_data_bit_offset] = "data_bit_offset",
      [DW_AT_const_expr] = "const_expr",
      [DW_AT_enum_class] = "enum_class",
      [DW_AT_linkage_name] = "linkage_name",
#endif
    };
  const unsigned int nknown_attrs = (sizeof (known_attrs)
				     / sizeof (known_attrs[0]));
  static char buf[40];
  const char *result = NULL;

  if (likely (attrnum < nknown_attrs))
    result = known_attrs[attrnum];

  if (unlikely (result == NULL))
    /* There are a few known extensions.  */
    switch (attrnum)
      {
      case DW_AT_MIPS_fde:
	result = "MIPS_fde";
	break;

      case DW_AT_MIPS_loop_begin:
	result = "MIPS_loop_begin";
	break;

      case DW_AT_MIPS_tail_loop_begin:
	result = "MIPS_tail_loop_begin";
	break;

      case DW_AT_MIPS_epilog_begin:
	result = "MIPS_epilog_begin";
	break;

      case DW_AT_MIPS_loop_unroll_factor:
	result = "MIPS_loop_unroll_factor";
	break;

      case DW_AT_MIPS_software_pipeline_depth:
	result = "MIPS_software_pipeline_depth";
	break;

      case DW_AT_MIPS_linkage_name:
	result = "MIPS_linkage_name";
	break;

      case DW_AT_MIPS_stride:
	result = "MIPS_stride";
	break;

      case DW_AT_MIPS_abstract_name:
	result = "MIPS_abstract_name";
	break;

      case DW_AT_MIPS_clone_origin:
	result = "MIPS_clone_origin";
	break;

      case DW_AT_MIPS_has_inlines:
	result = "MIPS_has_inlines";
	break;

      case DW_AT_MIPS_stride_byte:
	result = "MIPS_stride_byte";
	break;

      case DW_AT_MIPS_stride_elem:
	result = "MIPS_stride_elem";
	break;

      case DW_AT_MIPS_ptr_dopetype:
	result = "MIPS_ptr_dopetype";
	break;

      case DW_AT_MIPS_allocatable_dopetype:
	result = "MIPS_allocatable_dopetype";
	break;

      case DW_AT_MIPS_assumed_shape_dopetype:
	result = "MIPS_assumed_shape_dopetype";
	break;

      case DW_AT_MIPS_assumed_size:
	result = "MIPS_assumed_size";
	break;

      case DW_AT_sf_names:
	result = "sf_names";
	break;

      case DW_AT_src_info:
	result = "src_info";
	break;

      case DW_AT_mac_info:
	result = "mac_info";
	break;

      case DW_AT_src_coords:
	result = "src_coords";
	break;

      case DW_AT_body_begin:
	result = "body_begin";
	break;

      case DW_AT_body_end:
	result = "body_end";
	break;

#if HAVE_ELFUTILS_VERSION >= 152
      case DW_AT_GNU_vector:
	result = "GNU_vector";
	break;

      case DW_AT_GNU_template_name:
	result = "GNU_template_name";
	break;
#endif

      default:
	if (attrnum < DW_AT_lo_user)
	  snprintf (buf, sizeof buf, "unknown attribute %hx",
		    attrnum);
	else
	  snprintf (buf, sizeof buf, "unknown user attribute %hx",
		    attrnum);
	result = buf;
	break;
      }

  return result;
}


const char *
dwarf_form_string (unsigned int form)
{
  static const char *const known_forms[] =
    {
      [DW_FORM_addr] = "addr",
      [DW_FORM_block2] = "block2",
      [DW_FORM_block4] = "block4",
      [DW_FORM_data2] = "data2",
      [DW_FORM_data4] = "data4",
      [DW_FORM_data8] = "data8",
      [DW_FORM_string] = "string",
      [DW_FORM_block] = "block",
      [DW_FORM_block1] = "block1",
      [DW_FORM_data1] = "data1",
      [DW_FORM_flag] = "flag",
      [DW_FORM_sdata] = "sdata",
      [DW_FORM_strp] = "strp",
      [DW_FORM_udata] = "udata",
      [DW_FORM_ref_addr] = "ref_addr",
      [DW_FORM_ref1] = "ref1",
      [DW_FORM_ref2] = "ref2",
      [DW_FORM_ref4] = "ref4",
      [DW_FORM_ref8] = "ref8",
      [DW_FORM_ref_udata] = "ref_udata",
      [DW_FORM_indirect] = "indirect",
#if HAVE_ELFUTILS_VERSION >= 152
      [DW_FORM_sec_offset] = "sec_offset",
      [DW_FORM_exprloc] = "exprloc",
      [DW_FORM_flag_present] = "flag_present",
      [DW_FORM_ref_sig8] = "ref_sig8"
#endif
    };
  const unsigned int nknown_forms = (sizeof (known_forms)
				     / sizeof (known_forms[0]));
  static char buf[40];
  const char *result = NULL;

  if (likely (form < nknown_forms))
    result = known_forms[form];

  if (unlikely (result == NULL))
    snprintf (buf, sizeof buf, "unknown form %x",form);

  return result;
}


const char *
dwarf_lang_string (unsigned int lang)
{
  static const char *const known[] =
    {
      [DW_LANG_C89] = "ISO C89",
      [DW_LANG_C] = "C",
      [DW_LANG_Ada83] = "Ada83",
      [DW_LANG_C_plus_plus] = "C++",
      [DW_LANG_Cobol74] = "Cobol74",
      [DW_LANG_Cobol85] = "Cobol85",
      [DW_LANG_Fortran77] = "Fortran77",
      [DW_LANG_Fortran90] = "Fortran90",
      [DW_LANG_Pascal83] = "Pascal83",
      [DW_LANG_Modula2] = "Modula2",
      [DW_LANG_Java] = "Java",
      [DW_LANG_C99] = "ISO C99",
      [DW_LANG_Ada95] = "Ada95",
      [DW_LANG_Fortran95] = "Fortran95",
      [DW_LANG_PL1] = "PL1",
      [DW_LANG_Objc] = "Objective C",
      [DW_LANG_ObjC_plus_plus] = "Objective C++",
      [DW_LANG_UPC] = "UPC",
      [DW_LANG_D] = "D",
    };

  if (likely (lang < sizeof (known) / sizeof (known[0])))
    return known[lang];
  else if (lang == DW_LANG_Mips_Assembler)
    /* This language tag is used for assembler in general.  */
    return "Assembler";

  if (lang >= DW_LANG_lo_user && lang <= DW_LANG_hi_user)
    {
      static char buf[30];
      snprintf (buf, sizeof (buf), "lo_user+%u", lang - DW_LANG_lo_user);
      return buf;
    }

  return "???";
}


const char *
dwarf_inline_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_INL_not_inlined] = "not_inlined",
      [DW_INL_inlined] = "inlined",
      [DW_INL_declared_not_inlined] = "declared_not_inlined",
      [DW_INL_declared_inlined] = "declared_inlined"
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  return "???";
}


const char *
dwarf_encoding_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_ATE_void] = "void",
      [DW_ATE_address] = "address",
      [DW_ATE_boolean] = "boolean",
      [DW_ATE_complex_float] = "complex_float",
      [DW_ATE_float] = "float",
      [DW_ATE_signed] = "signed",
      [DW_ATE_signed_char] = "signed_char",
      [DW_ATE_unsigned] = "unsigned",
      [DW_ATE_unsigned_char] = "unsigned_char",
      [DW_ATE_imaginary_float] = "imaginary_float",
      [DW_ATE_packed_decimal] = "packed_decimal",
      [DW_ATE_numeric_string] = "numeric_string",
      [DW_ATE_edited] = "edited",
      [DW_ATE_signed_fixed] = "signed_fixed",
      [DW_ATE_unsigned_fixed] = "unsigned_fixed",
      [DW_ATE_decimal_float] = "decimal_float",
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  if (code >= DW_ATE_lo_user && code <= DW_ATE_hi_user)
    {
      static char buf[30];
      snprintf (buf, sizeof (buf), "lo_user+%u", code - DW_ATE_lo_user);
      return buf;
    }

  return "???";
}


const char *
dwarf_access_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_ACCESS_public] = "public",
      [DW_ACCESS_protected] = "protected",
      [DW_ACCESS_private] = "private"
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  return "???";
}


const char *
dwarf_visibility_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_VIS_local] = "local",
      [DW_VIS_exported] = "exported",
      [DW_VIS_qualified] = "qualified"
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  return "???";
}


const char *
dwarf_virtuality_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_VIRTUALITY_none] = "none",
      [DW_VIRTUALITY_virtual] = "virtual",
      [DW_VIRTUALITY_pure_virtual] = "pure_virtual"
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  return "???";
}


const char *
dwarf_identifier_case_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_ID_case_sensitive] = "sensitive",
      [DW_ID_up_case] = "up_case",
      [DW_ID_down_case] = "down_case",
      [DW_ID_case_insensitive] = "insensitive"
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  return "???";
}


const char *
dwarf_calling_convention_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_CC_normal] = "normal",
      [DW_CC_program] = "program",
      [DW_CC_nocall] = "nocall",
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  if (code >= DW_CC_lo_user && code <= DW_CC_hi_user)
    {
      static char buf[30];
      snprintf (buf, sizeof (buf), "lo_user+%u", code - DW_CC_lo_user);
      return buf;
    }

  return "???";
}


const char *
dwarf_ordering_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_ORD_row_major] = "row_major",
      [DW_ORD_col_major] = "col_major"
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  return "???";
}


const char *
dwarf_discr_list_string (unsigned int code)
{
  static const char *const known[] =
    {
      [DW_DSC_label] = "label",
      [DW_DSC_range] = "range"
    };

  if (likely (code < sizeof (known) / sizeof (known[0])))
    return known[code];

  return "???";
}
