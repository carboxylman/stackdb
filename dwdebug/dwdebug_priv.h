/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __DWDEBUG_PRIV_H__
#define __DWDEBUG_PRIV_H__

struct binfile *binfile_lookup(char *filename);
int binfile_cache(struct binfile *binfile);
int binfile_uncache(struct binfile *binfile);
/*
 * Internal versions; do not hold a ref to their return values!
 */
struct binfile *binfile_open__int(char *filename,char *root_prefix,
				  struct binfile_instance *bfinst);
struct binfile *binfile_open_debuginfo__int(struct binfile *binfile,
					    struct binfile_instance *bfinst,
					    const char *DFPATH[]);
REFCNT binfile_free(struct binfile *binfile,int force);


struct lsymbol *symtab_lookup_sym__int(struct symtab *symtab,
				       const char *name,const char *delim,
				       symbol_type_flag_t ftype);
struct lsymbol *symbol_lookup_sym__int(struct symbol *symbol,
				       const char *name,const char *delim);


/*
 * Creates an lsymbol data structure and takes references to all its
 * symbols.  Users should never call this function.
 *
 * This function takes a ref to each symbol in @chain, BUT NOT to
 * @return.
 */
struct lsymbol *lsymbol_create(struct symbol *symbol,struct array_list *chain);
/*
 * Add another symbol to the end of our lookup chain and make it the
 * primary symbol (i.e, @lsymbol->symbol = symbol), and hold a ref on
 * @symbol.  Users should not need to call this.
 */
void lsymbol_append(struct lsymbol *lsymbol,struct symbol *symbol);
/*
 * Add a symbol to the start of our lookup chain and hold a ref on
 * @symbol.  Users should not need to call this.
 */
void lsymbol_prepend(struct lsymbol *lsymbol,struct symbol *symbol);
/*
 * Takes references to the symbols on the lsymbol chain!.  Users should
 * never call this function unless they call lsymbol_create*(); the
 * lookup functions return lsymbols that have been held.  The user
 * should only call lsymbol_release on them.
 */
void lsymbol_hold_int(struct lsymbol *lsymbol);
/*
 * These functions take refs to each symbol in the lsymbol they create,
 * BUT NOT to @return (call lsymbol_hold() to get that ref).
 */

struct lsymbol *lsymbol_lookup_sym__int(struct lsymbol *lsymbol,
					const char *name,const char *delim);
struct lsymbol *lsymbol_create_from_member__int(struct lsymbol *parent,
						struct symbol *member);
struct lsymbol *lsymbol_create_from_symbol__int(struct symbol *symbol);
struct lsymbol *lsymbol_create_noninline__int(struct lsymbol *lsymbol);

/*
 * Releases references to the symbols on the chain and tries to free the
 * lsymbol (not the underlying symbols!).
 */
REFCNT lsymbol_free(struct lsymbol *lsymbol,int force);

struct lsymbol *debugfile_lookup_addr__int(struct debugfile *debugfile,ADDR addr);

struct lsymbol *debugfile_lookup_sym__int(struct debugfile *debugfile,
					  char *name,const char *delim,
					  struct rfilter *srcfile_filter,
					  symbol_type_flag_t ftype);
struct lsymbol *debugfile_lookup_sym_line__int(struct debugfile *debugfile,
					       char *filename,int line,
					       SMOFFSET *offset,ADDR *addr);

struct symbol *symbol_get_one_member__int(struct symbol *symbol,char *member,
					  struct array_list **chainptr);
struct symbol *symbol_get_datatype__int(struct symbol *symbol);


void debugfile_handle_declaration(struct debugfile *debugfile,
				  struct symbol *symbol);
void debugfile_resolve_declarations(struct debugfile *debugfile);

REFCNT debugfile_free(struct debugfile *debugfile,int force);

#endif
