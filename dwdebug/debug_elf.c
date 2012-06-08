/*
 * Copyright (c) 2011, 2012 The University of Utah
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <regex.h>

#include "config.h"
#include "log.h"
#include "output.h"
#include "list.h"
#include "alist.h"
#include "dwdebug.h"

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

#include "memory-access.h"

int elf_get_base_addrs(Elf *elf,
		       ADDR *base_virt_addr_saveptr,
		       ADDR *base_phys_addr_saveptr) {
    GElf_Ehdr ehdr_mem;
    GElf_Ehdr *ehdr;
    GElf_Phdr phdr_mem;
    GElf_Phdr *phdr;
    size_t i;
    ADDR base_phys_addr = 0;
    ADDR base_virt_addr = 0;

    /*
     * Search through all the program headers; for those of type LOAD,
     * find the minimum phys addr (and its corresponding virt addr);
     * take these addrs to be used in calculating the phys_offset later
     * for use in virt<->phys addr translation from debuginfo virt addrs
     * to phys machine addrs.
     */
    ehdr = gelf_getehdr(elf,&ehdr_mem);
    if (ehdr && ehdr->e_phnum > 0) {
	base_phys_addr = ADDRMAX;
	base_virt_addr = ADDRMAX;

	for (i = 0; i < ehdr->e_phnum; ++i) {
	    if (!(phdr = gelf_getphdr(elf,i,&phdr_mem))) {
		vwarn("could not read program header %d\n",(int)i);
		continue;
	    }

	    if (phdr->p_type != PT_LOAD)
		continue;

	    if (phdr->p_vaddr < base_virt_addr) {
		base_phys_addr = phdr->p_paddr;
		base_virt_addr = phdr->p_vaddr;
	    }
	}
    }

    /* If we didn't find anything (weird), make sure to use 0 as our
     * base; it's the best we can do, realistically.
     */
    if (base_phys_addr == ADDRMAX && base_virt_addr == ADDRMAX) 
	base_phys_addr = base_virt_addr = 0;

    if (base_phys_addr_saveptr)
	*base_phys_addr_saveptr = base_phys_addr;
    if (base_virt_addr_saveptr)
	*base_virt_addr_saveptr = base_virt_addr;

    return 0;
}

int elf_get_debuginfo_info(Elf *elf,
			   int *has_debuginfo_saveptr,
			   char **buildid_saveptr,
			   char **gnu_debuglinkfile_saveptr,
			   uint32_t *gnu_debuglinkfile_crc_saveptr) {
    Elf_Scn *scn;
    GElf_Shdr shdr_mem;
    GElf_Shdr *shdr;
    size_t shstrndx;
    Elf_Data *edata;
    int is64;
    Elf32_Nhdr *nthdr32;
    Elf64_Nhdr *nthdr64;
    char *ndata,*nend;
    char *name;

    int has_debuginfo = 0;
    char *buildid = NULL;
    char *debuglinkfile = NULL;
    uint32_t debuglinkfilecrc = 0;

    if (elf_get_arch_info(elf,&is64,NULL)) {
	verror("elf_get_arch_info failed\n");
	return -1;
    }
    is64 = (is64 == 8) ? 1 : 0;

#if _INT_ELFUTILS_VERSION >= 152
    if (elf_getshdrstrndx(elf,&shstrndx) < 0) {
#else 
    if (elf_getshstrndx(elf,&shstrndx) < 0) {
#endif
	verror("cannot get section header string table index\n");
	return -1;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr && shdr->sh_size > 0) {
	    name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".debug_info") == 0) {
		vdebug(2,LOG_T_LUP,
		       "found %s section (%d)\n",name,shdr->sh_size);
		has_debuginfo = 1;
		continue;
	    }
	    else if (!buildid && shdr->sh_type == SHT_NOTE) {
		vdebug(2,LOG_T_LUP,
		       "found %s note section (%d)\n",name,shdr->sh_size);
		edata = elf_rawdata(scn,NULL);
		if (!edata) {
		    vwarn("cannot get data for valid section '%s': %s",
			  name,elf_errmsg(-1));
		    continue;
		}

		ndata = edata->d_buf;
		nend = ndata + edata->d_size;
		while (ndata < nend) {
		    if (is64) {
			nthdr64 = (Elf64_Nhdr *)ndata;
			/* skip past the header and the name string and its
			 * padding */
			ndata += sizeof(Elf64_Nhdr);
			vdebug(5,LOG_T_LUP,"found note name '%s'\n",ndata);
			ndata += nthdr64->n_namesz;
			if (nthdr64->n_namesz % 4)
			    ndata += (4 - nthdr64->n_namesz % 4);
			vdebug(5,LOG_T_LUP,"found note desc '%s'\n",ndata);
			/* dig out the build ID */
			if (nthdr64->n_type == NT_GNU_BUILD_ID) {
			    buildid = strdup(ndata);
			    break;
			}
			/* skip past the descriptor and padding */
			ndata += nthdr64->n_descsz;
			if (nthdr64->n_namesz % 4)
			    ndata += (4 - nthdr64->n_namesz % 4);
		    }
		    else {
			nthdr32 = (Elf32_Nhdr *)ndata;
			/* skip past the header and the name string and its
			 * padding */
			ndata += sizeof(Elf32_Nhdr);
			ndata += nthdr32->n_namesz;
			if (nthdr32->n_namesz % 4)
			    ndata += (4 - nthdr32->n_namesz % 4);
			/* dig out the build ID */
			if (nthdr32->n_type == NT_GNU_BUILD_ID) {
			    buildid = strdup(ndata);
			    break;
			}
			/* skip past the descriptor and padding */
			ndata += nthdr32->n_descsz;
			if (nthdr32->n_namesz % 4)
			    ndata += (4 - nthdr32->n_namesz % 4);
		    }
		}
	    }
	    else if (strcmp(name,".gnu_debuglink") == 0) {
		edata = elf_rawdata(scn,NULL);
		if (!edata) {
		    vwarn("cannot get data for valid section '%s': %s",
			  name,elf_errmsg(-1));
		    continue;
		}
		debuglinkfile = strdup(edata->d_buf);
		debuglinkfilecrc = *(uint32_t *)(edata->d_buf + edata->d_size - 4);
	    }
	}
    }

    if (has_debuginfo_saveptr)
	*has_debuginfo_saveptr = has_debuginfo;
    if (buildid_saveptr)
	*buildid_saveptr = buildid;
    else if (buildid)
	free(buildid);
    if (gnu_debuglinkfile_saveptr)
	*gnu_debuglinkfile_saveptr = debuglinkfile;
    else if (debuglinkfile)
	free(debuglinkfile);
    if (gnu_debuglinkfile_crc_saveptr)
	*gnu_debuglinkfile_crc_saveptr = debuglinkfilecrc;

    return 0;
}

int elf_get_arch_info(Elf *elf,int *wordsize,int *endian) {
    char *eident;

    /* read the ident stuff to get wordsize and endianness info */
    if (!(eident = elf_getident(elf,NULL))) {
	verror("elf_getident: %s\n",elf_errmsg(elf_errno()));
	return -1;
    }

    if ((uint8_t)eident[EI_CLASS] == ELFCLASS32) {
	if (wordsize)
	    *wordsize = 4;
	vdebug(3,LOG_D_ELF,"32-bit\n");
    }
    else if ((uint8_t)eident[EI_CLASS] == ELFCLASS64) {
	if (wordsize) 
	    *wordsize = 8;
	vdebug(3,LOG_D_ELF,"64-bit\n");
    }
    else {
	verror("unknown elf class %d; not 32/64 bit!\n",
	       (uint8_t)eident[EI_CLASS]);
	return -1;
    }

    if ((uint8_t)eident[EI_DATA] == ELFDATA2LSB) {
	if (endian)
	    *endian = DATA_LITTLE_ENDIAN;
	vdebug(3,LOG_T_LUP,"little endian\n");
    }
    else if ((uint8_t)eident[EI_DATA] == ELFDATA2MSB) {
	if (endian)
	    *endian = DATA_BIG_ENDIAN;
	vdebug(3,LOG_T_LUP,"big endian\n");
    }
    else {
	verror("unknown elf data %d; not big/little endian!\n",
	       (uint8_t)eident[EI_DATA]);
	return -1;
    }

    return 0;
}

int elf_is_dynamic_exe(Elf *elf) {
    Elf_Scn *scn;
    GElf_Shdr shdr_mem;
    GElf_Shdr *shdr;
    char *name;
    size_t shstrndx;

#if _INT_ELFUTILS_VERSION >= 152
    if (elf_getshdrstrndx(elf,&shstrndx) < 0) {
#else 
    if (elf_getshstrndx(elf,&shstrndx) < 0) {
#endif
	verror("cannot get section header string table index\n");
	return -1;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr && shdr->sh_size > 0) {
	    name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".dynamic") == 0) {
		vdebug(2,LOG_D_ELF,
		       "found %s section (%d); ELF file is dynamic\n",
		       name,shdr->sh_size);
		return 1;
	    }
	}
    }

    vdebug(2,LOG_D_ELF,"ELF file is static\n");
    return 0;
}


int elf_load_symtab(Elf *elf,char *elf_filename,struct debugfile *debugfile) {
    Elf_Scn *scn = NULL;
    size_t shstrndx;
    GElf_Ehdr ehdr_mem;
    GElf_Ehdr *ehdr;
    Ebl *ebl;
    Elf_Data *edata;
    unsigned int i;
    int class;
    char *name;
    GElf_Shdr shdr_mem;
    GElf_Shdr *shdr;
    unsigned int nsyms;
    GElf_Sym sym_mem;
    GElf_Sym *sym;
    char *symname;
    unsigned char stt;
    struct symbol *symbol;
    int *section_flags = NULL;

    if (!(ehdr = gelf_getehdr(elf,&ehdr_mem))) {
	verror("cannot read ELF header: %s",elf_errmsg(-1));
	return -1;
    }

    ebl = ebl_openbackend(elf);
    if (ebl == NULL) {
	verror("cannot create EBL handle: %s",strerror(errno));
	return -1;
    }

    class = gelf_getclass(elf);

#if _INT_ELFUTILS_VERSION >= 152
    if (elf_getshdrstrndx(elf,&shstrndx) < 0) {
#else 
    if (elf_getshstrndx(elf,&shstrndx) < 0) {
#endif
	verror("cannot get section header string table index\n");
	goto errout;
    }

    /* Scan for strtab section */
    scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr && shdr->sh_size > 0 && shdr->sh_type == SHT_STRTAB) {
	    name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".strtab") != 0) 
		continue;

	    vdebug(2,LOG_D_DWARF,
		   "found .strtab section in ELF file %s\n",
		   elf_filename);

	    edata = elf_rawdata(scn,NULL);
	    if (!edata || !edata->d_size || !edata->d_buf) {
		verror("cannot get data for valid section %s in %s: %s",
		       name,elf_filename,elf_errmsg(-1));
		goto errout;
	    }

	    debugfile->elf_strtablen = edata->d_size;
	    debugfile->elf_strtab = malloc(edata->d_size);
	    memcpy(debugfile->elf_strtab,edata->d_buf,edata->d_size);
	    break;
	}
    }

    if (!debugfile->elf_strtab) {
	vwarn("could not find .strtab for ELF file %s; cannot load .symtab!\n",
	      elf_filename);
	goto errout;
    }

    /* 
     * Now scan all the section headers and build up a simple array of
     * the section flags, so we know for the STT_NOTYPE symbols what
     * they *probably* are.
     */
    section_flags = (int *)malloc(sizeof(int)*ehdr->e_shnum);
    memset(section_flags,0,sizeof(int)*ehdr->e_shnum);

    for (i = 0; i < ehdr->e_shnum; ++i) {
	scn = elf_getscn(elf,i);
	shdr = gelf_getshdr(scn,&shdr_mem);

	section_flags[i] = shdr->sh_flags;
    }

    /* Now rescan for symtab section */
    scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr && shdr->sh_size > 0 && shdr->sh_type == SHT_SYMTAB) {
	    name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".symtab") != 0) 
		continue;

	    vdebug(2,LOG_D_DWARF,
		   "found .symtab section in ELF file %s\n",
		   elf_filename);

	    edata = elf_getdata(scn,NULL);
	    if (!edata || !edata->d_size || !edata->d_buf) {
		verror("cannot get data for valid section %s in %s: %s",
		       name,elf_filename,elf_errmsg(-1));
		goto errout;
	    }

	    nsyms = edata->d_size / (class == ELFCLASS32 ? sizeof (Elf32_Sym) \
				                         : sizeof (Elf64_Sym));

	    vdebug(2,LOG_D_DWARF,
		   ".symtab section in ELF file %s has %d symbols\n",
		   elf_filename,nsyms);

	    /* Load the symtab */
	    for (i = 0; i < nsyms; ++i) {
		sym = gelf_getsym(edata,i,&sym_mem);
		if (sym->st_name >= debugfile->elf_strtablen) {
		    vwarn("skipping ELF symbol with bad name strtab idx %d\n",
			  (int)sym->st_name);
		    continue;
		}

		stt = GELF_ST_TYPE(sym->st_info);

		/*
		 * If the symbol type is NOTYPE, check to see which
		 * section the symbol is in, and try to dynamically
		 * "set" the type to STT_OBJECT or STT_FUNC.  This will
		 * result in symbols that should not be in the ELF
		 * symtab, probably, but hopefully it will reduce the
		 * amount of missing symbols in our ELF symtab.
		 */
		if (stt == STT_NOTYPE && sym->st_shndx < ehdr->e_shnum) {
		    if (section_flags[sym->st_shndx] & SHF_EXECINSTR)
			stt = STT_FUNC;
		    else if (section_flags[sym->st_shndx] & SHF_ALLOC)
			stt = STT_OBJECT;
		}

		if (!(stt == STT_OBJECT || stt == STT_COMMON || stt == STT_TLS
		      || stt == STT_FUNC))
		    /* Skip all non-code symbols */
		    continue;

#ifdef DWDEBUG_USE_STRTAB
		symname = strdup(&debugfile->elf_strtab[sym->st_name]);
#else
		symname = &debugfile->elf_strtab[sym->st_name];
#endif

		symbol = symbol_create(debugfile->elf_symtab,(SMOFFSET)i,symname,
				       (stt == STT_OBJECT || stt == STT_TLS
					|| stt == STT_COMMON)	\
				       ? SYMBOL_TYPE_VAR	\
				       : SYMBOL_TYPE_FUNCTION,
				       SYMBOL_SOURCE_ELF,0);

		if (GELF_ST_BIND(sym->st_info) == STB_GLOBAL
		    || GELF_ST_BIND(sym->st_info) == STB_WEAK)
		    symbol->isexternal = 1;

		symbol->size = sym->st_size;

		symbol->base_addr = (ADDR)sym->st_value;

		symtab_insert(debugfile->elf_symtab,symbol,0);

		/*
		 * Insert into debugfile->addresses IF the hashtable is
		 * empty (i.e., if we load the symtab first, before the
		 * debuginfo file), or if there is not anything already
		 * at this location.  We want debuginfo symbols to trump
		 * ELF symbols in this table.
		 */
		if (g_hash_table_size(debugfile->addresses) == 0
		    || !g_hash_table_lookup(debugfile->addresses,
					    (gpointer)symbol->base_addr))
		    g_hash_table_insert(debugfile->addresses,
					(gpointer)symbol->base_addr,
					(gpointer)symbol);

		if (symbol->base_addr != 0)
		    clrange_add(&debugfile->elf_ranges,symbol->base_addr,
				symbol->base_addr + symbol->size,symbol);
	    }
	}
    }

#ifndef DWDEBUG_USE_STRTAB
    /*
     * Only save elf_strtab if we're gonna use it.
     */
    if (debugfile->elf_strtab) {
	free(debugfile->elf_strtab);
	debugfile->elf_strtablen = 0;
	debugfile->elf_strtab = NULL;
    }
#endif

 out:
    if (section_flags)
	free(section_flags);
    ebl_closebackend(ebl);
    return 0;

 errout:
    if (section_flags)
	free(section_flags);
    if (debugfile->elf_strtab)
	free(debugfile->elf_strtab);
    ebl_closebackend(ebl);
    return -1;
}
