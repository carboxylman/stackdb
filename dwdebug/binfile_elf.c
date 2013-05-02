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
#include "common.h"
#include "log.h"
#include "output.h"
#include "list.h"
#include "clfit.h"
#include "alist.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

#include "memory-access.h"


static const char *elf_binfile_get_backend_name(void);
static struct binfile *elf_binfile_open(char *filename,
					struct binfile_instance *bfinst);
static struct binfile *elf_binfile_open_debuginfo(struct binfile *binfile,
						  struct binfile_instance *bfinst,
						  const char *DFPATH[]);
static struct binfile_instance *elf_binfile_infer_instance(struct binfile *binfile,
							   ADDR base,
							   GHashTable *config);
static int elf_binfile_close(struct binfile *binfile);
static void elf_binfile_free(struct binfile *binfile);
static void elf_binfile_free_instance(struct binfile_instance *bfi);

struct binfile_ops elf_binfile_ops = {
    .get_backend_name = elf_binfile_get_backend_name,
    .open = elf_binfile_open,
    .open_debuginfo = elf_binfile_open_debuginfo,
    .infer_instance = elf_binfile_infer_instance,
    .close = elf_binfile_close,
    .free = elf_binfile_free,
    .free_instance = elf_binfile_free_instance,
};

static int elf_get_arch_info(Elf *elf,int *wordsize,int *endian) {
    char *eident;

    /* read the ident stuff to get wordsize and endianness info */
    if (!(eident = elf_getident(elf,NULL))) {
	verror("elf_getident: %s\n",elf_errmsg(elf_errno()));
	return -1;
    }

    if ((uint8_t)eident[EI_CLASS] == ELFCLASS32) {
	if (wordsize)
	    *wordsize = 4;
	vdebug(3,LA_DEBUG,LF_ELF,"32-bit\n");
    }
    else if ((uint8_t)eident[EI_CLASS] == ELFCLASS64) {
	if (wordsize) 
	    *wordsize = 8;
	vdebug(3,LA_DEBUG,LF_ELF,"64-bit\n");
    }
    else {
	verror("unknown elf class %d; not 32/64 bit!\n",
	       (uint8_t)eident[EI_CLASS]);
	return -1;
    }

    if ((uint8_t)eident[EI_DATA] == ELFDATA2LSB) {
	if (endian)
	    *endian = DATA_LITTLE_ENDIAN;
	vdebug(3,LA_DEBUG,LF_DFILE,"little endian\n");
    }
    else if ((uint8_t)eident[EI_DATA] == ELFDATA2MSB) {
	if (endian)
	    *endian = DATA_BIG_ENDIAN;
	vdebug(3,LA_DEBUG,LF_DFILE,"big endian\n");
    }
    else {
	verror("unknown elf data %d; not big/little endian!\n",
	       (uint8_t)eident[EI_DATA]);
	return -1;
    }

    return 0;
}

static const char *elf_binfile_get_backend_name(void) {
    return "elf";
}

static int elf_binfile_close(struct binfile *binfile) {
    struct binfile_elf *bfelf = (struct binfile_elf *)binfile->priv;

    if (bfelf->ebl) {
	ebl_closebackend(bfelf->ebl);
	bfelf->ebl = NULL;
    }
    if (bfelf->dwfl) {
	dwfl_end(bfelf->dwfl);
	bfelf->dwfl = NULL;
    }
    if (bfelf->elf) {
	elf_end(bfelf->elf);
	bfelf->elf = NULL;
    }
    if (binfile->fd > -1) {
	close(binfile->fd);
	binfile->fd = -1;
    }
    if (binfile->image) {
	free(binfile->image);
	binfile->image = NULL;
    }

    return 0;
}

static void elf_binfile_free(struct binfile *binfile) {
    struct binfile_elf *bfelf = (struct binfile_elf *)binfile->priv;
    struct binfile_instance *bfi = (struct binfile_instance *)binfile->instance;
    struct binfile_instance_elf *bfielf = NULL;

    elf_binfile_close(binfile);

    if (bfi) {
	bfielf = (struct binfile_instance_elf *)bfi->priv;

	if (bfielf) {
	    if (bfielf->section_tab) {
		free(bfielf->section_tab);
		bfielf->section_tab = NULL;
	    }
	    if (bfielf->symbol_tab) {
		free(bfielf->symbol_tab);
		bfielf->symbol_tab = NULL;
	    }
	    free(bfielf);
	    bfi->priv = NULL;
	}
    }

    if (bfelf->shdrs) {
	free(bfelf->shdrs);
	bfelf->shdrs = NULL;
    }
    if (bfelf->phdrs) {
	free(bfelf->phdrs);
	bfelf->phdrs = NULL;
    }
    if (bfelf->buildid) {
	free(bfelf->buildid);
	bfelf->buildid = NULL;
    }
    if (bfelf->gnu_debuglinkfile) {
	free(bfelf->gnu_debuglinkfile);
	bfelf->gnu_debuglinkfile = NULL;
    }

    free(binfile->priv);
}

static void elf_binfile_free_instance(struct binfile_instance *bfi) {
    struct binfile_instance_elf *bfielf = \
	(struct binfile_instance_elf *)bfi->priv;

    if (bfielf) {
	if (bfielf->shdrs) {
	    free(bfielf->shdrs);
	    bfielf->shdrs = NULL;
	}
	if (bfielf->section_tab) {
	    free(bfielf->section_tab);
	    bfielf->section_tab = NULL;
	}
	if (bfielf->symbol_tab) {
	    free(bfielf->symbol_tab);
	    bfielf->symbol_tab = NULL;
	}
	free(bfielf);
	bfi->priv = NULL;
    }
}

struct binfile *elf_binfile_open_debuginfo(struct binfile *binfile,
					   struct binfile_instance *bfinst,
					   const char *DFPATH[]) {
    struct binfile_elf *bfelf = (struct binfile_elf *)binfile->priv;
    char pbuf[PATH_MAX];
    struct stat stbuf;
    char *finalfile = NULL;
    int len;
    int i;
    char *filedir;
    char *tmp;

    /*
     * Read the debuginfo info from the given binary and figure out if
     * we should load from this file, or load from a pointed-to
     * debugfile.
     */

    vdebug(5,LA_DEBUG,LF_DFILE,"ELF info for file %s:\n",binfile->filename);
    vdebug(5,LA_DEBUG,LF_DFILE,"    has_debuginfo=%d,buildid='",
	   (int)binfile->has_debuginfo);
    if (bfelf->buildid) {
	len = (int)strlen(bfelf->buildid);
	for (i = 0; i < len; ++i)
	    vdebugc(5,LA_DEBUG,LF_DFILE,"%hhx",bfelf->buildid[i]);
    }
    vdebugc(5,LA_DEBUG,LF_DFILE,"'\n");
    vdebug(5,LA_DEBUG,LF_DFILE,"    debuglinkfile=%s,debuglinkfilecrc=0x%x\n",
	   bfelf->gnu_debuglinkfile,bfelf->gnu_debuglinkfile_crc);

    if (binfile->has_debuginfo) 
	return binfile;

    if (bfelf->buildid) {
	for (i = 0; DFPATH[i]; ++i) {
	    snprintf(pbuf,PATH_MAX,"%s/.build-id/%02hhx/%s.debug",
		     DFPATH[i],*bfelf->buildid,(char *)(bfelf->buildid+1));
	    if (stat(pbuf,&stbuf) == 0) {
		finalfile = pbuf;
		break;
	    }
	}
    }

    if (!finalfile && bfelf->gnu_debuglinkfile) {
	/* Find the containing dir path so we can use it in our search
	 * of the standard debug file dir infrastructure.
	 */
	filedir = strdup(binfile->filename);
	tmp = rindex(filedir,'/');
	if (tmp)
	    *tmp = '\0';
	for (i = 0; DFPATH[i]; ++i) {
	    snprintf(pbuf,PATH_MAX,"%s/%s/%s",
		     DFPATH[i],filedir,bfelf->gnu_debuglinkfile);
	    if (stat(pbuf,&stbuf) == 0) {
		finalfile = pbuf;
		break;
	    }
	}
	free(filedir);
    }

    if (!finalfile) {
	vwarnopt(1,LA_DEBUG,LF_ELF,
		 "no debuginfo sources associated with %s\n",binfile->filename);
	errno = ENODATA;
	return NULL;
    }

    /*
     * Open the file!
     */
    return binfile_open__int(finalfile,bfinst);
}

static struct binfile_instance *elf_binfile_infer_instance(struct binfile *binfile,
							   ADDR base,
							   GHashTable *config) {
    struct binfile_elf *bfelf;
    struct binfile_instance *bfi;
    struct binfile_instance_elf *bfielf;
    /*
     * This is the order the kernel module order lays out sections; see
     * kernel/module.c:layout_sections .  We use their algorithm for
     * layout too.  So, first layout exec&alloc sections that are not
     * arch-specific (not on the x86 at all); then alloc-only sections
     * that are not writeable; then alloc&writeable sections that are
     * not small; then small&alloc sections.
     *
     * Of course this layout is 
     */
#define ARCH_SHF_X86 0
    static unsigned long const shfm[][2] = {
	{ SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_X86 },
	{ SHF_ALLOC, SHF_WRITE | ARCH_SHF_X86 },
	{ SHF_WRITE | SHF_ALLOC, ARCH_SHF_X86 },
	{ ARCH_SHF_X86 | SHF_ALLOC, 0 }
    };
    unsigned int fm;
    unsigned int i;
    ADDR size = 0;
    ADDR align;
    GElf_Shdr *shdr;
    GElf_Sym sym_mem;
    GElf_Sym *sym;
    char *secname;
    Elf_Scn *scn;
    Elf_Data *edata;
    uint8_t *done_sections;
    char *kallsyms_str;
    int kallsyms = 0;

    if (!(bfelf = (struct binfile_elf *)binfile->priv)) {
	verror("no ELF info for source binfile %s!\n",binfile->filename);
	errno = EINVAL;
	return NULL;
    }

    bfi = calloc(1,sizeof(*bfi));
    bfielf = calloc(1,sizeof(*bfielf));

    bfi->filename = strdup(binfile->filename);
    bfi->base = base;
    bfi->ops = binfile->ops;
    bfi->priv = bfielf;

    bfielf->num_sections = bfelf->ehdr.e_shnum;
    bfielf->section_tab = calloc(bfielf->num_sections,sizeof(ADDR));

    done_sections = calloc(bfielf->num_sections,sizeof(uint8_t));

    /*
     * Some special kernel hacks!  Don't load modinfo, and load
     * symtab/strtab if CONFIG_KALLSYMS was set.  Need to tweak the
     * shdrs to stop modinfo from being alloc'd, and to alloc
     * symtab/strtab.
     */
    if (config) {
	kallsyms_str = g_hash_table_lookup(config,"CONFIG_KALLSYMS");
	if (kallsyms_str && (*kallsyms_str == 'y' || *kallsyms_str == 'Y'))
	    kallsyms = 1;
    }

    /*
     * This is very bad of us -- because we edit the cached section
     * headers in memory, and the underlying ELF descriptor does not
     * know.
     *
     * So, we save a copy in the instance, and edit that copy.  Anything
     * that uses our instance needs to know this.  We only use this for
     * relocatable ELF files that we relocate (and load into memory to
     * do the relocations on -- so we modify the relocated, in-memory
     * ELF descriptor in that case.  See elf_binfile_open...
     *
     * But, for this function, note that we use the edited shdrs!!
     */
    bfielf->shdrs = calloc(bfelf->ehdr.e_shnum,sizeof(*bfelf->shdrs));
    memcpy(bfielf->shdrs,bfelf->shdrs,bfelf->ehdr.e_shnum*sizeof(*bfelf->shdrs));

    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	shdr = &bfielf->shdrs[i];
	secname = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	if (kallsyms && (strcmp(secname,".symtab") == 0
			 || strcmp(secname,".strtab") == 0))
	    bfielf->shdrs[i].sh_flags |= SHF_ALLOC;
	else if (strcmp(secname,".modinfo") == 0) 
	    bfielf->shdrs[i].sh_flags &= ~(unsigned long)SHF_ALLOC;
    }

    /*
     * For now, the default layout is the kernel's layout :).  Those are
     * the only relocatable files we have to handle initially.
     */
    for (fm = 0; fm < sizeof(shfm)/(2*sizeof(unsigned long)); ++fm) {
	for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	    shdr = &bfielf->shdrs[i];
	    secname = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	    if ((shdr->sh_flags & shfm[fm][0]) != shfm[fm][0]
		|| shdr->sh_flags & shfm[fm][1]
		|| done_sections[i] != 0
		|| !secname
		|| strncmp(secname,".init",5) == 0)
		continue;

	    align = shdr->sh_addralign ? shdr->sh_addralign : 1;
	    bfielf->section_tab[i] = (size + align -1) & ~(align - 1);
	    size = bfielf->section_tab[i] + shdr->sh_size;
	    bfielf->section_tab[i] += base;

	    vdebug(3,LA_DEBUG,LF_ELF,
		   "section %d (%s) placed at 0x%"PRIxADDR" (0x%"PRIxADDR"+%ld)\n",
		   i,secname,bfielf->section_tab[i],base,
		   bfielf->section_tab[i] - base);

	    done_sections[i] = 1;

	    if (bfi->start < bfi->base)
		bfi->start = bfielf->section_tab[i];
	    else if (bfielf->section_tab[i] < bfi->start)
		bfi->start = bfielf->section_tab[i];

	    if (bfielf->section_tab[i] > bfi->end)
		bfi->end = bfielf->section_tab[i];
	}
    }

    for (fm = 0; fm < sizeof(shfm)/(2*sizeof(unsigned long)); ++fm) {
	for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	    shdr = &bfielf->shdrs[i];
	    secname = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	    if ((shdr->sh_flags & shfm[fm][0]) != shfm[fm][0]
		|| shdr->sh_flags & shfm[fm][1]
		|| done_sections[i] != 0
		|| !secname || strncmp(secname,".init",5) != 0)
		continue;

	    align = shdr->sh_addralign ? shdr->sh_addralign : 1;
	    bfielf->section_tab[i] = (size + align -1) & ~(align - 1);
	    size = bfielf->section_tab[i] + shdr->sh_size;
	    bfielf->section_tab[i] += base;

	    vdebug(3,LA_DEBUG,LF_ELF,
		   "section %d (%s) placed at 0x%"PRIxADDR" (0x%"PRIxADDR"+%ld)\n",
		   i,secname,bfielf->section_tab[i],base,
		   bfielf->section_tab[i] - base);

	    done_sections[i] = 1;

	    if (bfi->start < bfi->base)
		bfi->start = bfielf->section_tab[i];
	    else if (bfielf->section_tab[i] < bfi->start)
		bfi->start = bfielf->section_tab[i];

	    if (bfielf->section_tab[i] > bfi->end)
		bfi->end = bfielf->section_tab[i];
	}
    }

    free(done_sections);

    /*
     * Take a spin over the symtab, and fill in our local entries.  We
     * could also wait until the binfile is opened against the instance,
     * but I suppose the user might not do that.  So do it here... sigh.
     */
    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	shdr = &bfielf->shdrs[i];

	if (!shdr || shdr->sh_size <= 0 || shdr->sh_type != SHT_SYMTAB) 
	    continue;

	secname = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	if (strcmp(secname,".symtab") != 0) 
	    continue;

	vdebug(2,LA_DEBUG,LF_ELF,"found .symtab section in ELF file %s\n",
	       binfile->filename);

	scn = elf_getscn(bfelf->elf,i);
	edata = elf_getdata(scn,NULL);
	if (!edata || !edata->d_size || !edata->d_buf) {
	    verror("cannot get data for valid section %s in %s: %s (skipping)\n",
		   secname,binfile->filename,elf_errmsg(-1));
	    goto errout;
	}

	bfielf->num_symbols = \
	    edata->d_size / (bfelf->class == ELFCLASS32 ? sizeof (Elf32_Sym) \
			                                : sizeof (Elf64_Sym));
	bfielf->symbol_tab = \
	    calloc(bfielf->num_symbols,sizeof(*bfielf->symbol_tab));

	vdebug(2,LA_DEBUG,LF_ELF,
	       ".symtab section in ELF file %s has %d symbols\n",
	       binfile->filename,bfielf->num_symbols);

	/* Load the symtab */
	for (i = 0; i < bfielf->num_symbols; ++i) {
	    sym = gelf_getsym(edata,i,&sym_mem);

	    if (GELF_ST_TYPE(sym->st_info) == STT_SECTION) {
		bfielf->symbol_tab[i] = bfielf->section_tab[sym->st_shndx];
	    }
	    else if ((GELF_ST_TYPE(sym->st_info) == STT_OBJECT
		      || GELF_ST_TYPE(sym->st_info) == STT_FUNC)
		     && sym->st_shndx != SHN_UNDEF
		     && sym->st_shndx != SHN_ABS
		     && sym->st_shndx != SHN_COMMON) {
		bfielf->symbol_tab[i] = bfielf->section_tab[sym->st_shndx] 
		    + sym->st_value;
	    }
	    else {
		continue;
	    }
	}
    }

 errout:

    return bfi;
}

static struct binfile *elf_binfile_open(char *filename,
					struct binfile_instance *bfinst) {
    struct binfile *bf = NULL;
    struct binfile_elf *bfelf = NULL;
    Elf_Scn *scn = NULL;
    GElf_Phdr *phdr;
    GElf_Shdr *shdr;
    char *name;
    Elf_Data *edata;
    struct array_list *ral;
    struct clf_range_data *crd;
    struct array_list *tmp_ral;
    struct clf_range_data *tmp_crd;
    struct symbol *tmp_symbol;
    struct clf_range_data *gcrd;
    GElf_Sym sym_mem;
    GElf_Sym *sym;
    char *symname;
    unsigned char stt;
    struct symbol *symbol;
    unsigned int i, ii;
    int j,k;
    Word_t nextstart = -1;
    Word_t tmpstart = -1;
    Word_t start = -1;
    Word_t end = -1;
    Elf32_Nhdr *nthdr32;
    Elf64_Nhdr *nthdr64;
    char *ndata,*nend;
    struct stat stbuf;
    int rci, rc;
    int fdi;
    GElf_Rel rel;
    int nrels;
    Elf_Scn *rstscn;
    Elf_Data *rstedata;
    int rsec;
    int rstsec;
    GElf_Sym rsym;
    int rsymidx;
    int rtype;
    int rcoffset;
    GElf_Addr rvalue;
    struct binfile_instance_elf *bfelfinst = NULL;
    GElf_Shdr *shdr_new;
    GElf_Shdr shdr_new_mem;
    int sec_found;
    Word_t sec_end;
    int has_plt = 0;
    Word_t plt_start = 0;
    Word_t plt_size = 0;
    int plt_idx;
    int plt_entry_size = 0;
    int len;
    char *pltsymbuf;
    GElf_Rela rela;
    int rstrsec;
    int dynsymtabsec = -1;
    int symtabsec = -1;
    int dynstrtabsec = -1;
    int strtabsec = -1;
    struct symbol *tsymbol;

    /*
     * Set up our data structures.
     */
    bfelf = (struct binfile_elf *)calloc(1,sizeof(*bfelf));
    if (!bfelf) 
	goto errout;
    bfelf->dwfl_fd = -1;

    bf = binfile_create(filename,&elf_binfile_ops,bfelf);
    if (!bf) 
	goto errout;

    if (bfinst)
	bfelfinst = (struct binfile_instance_elf *)bfinst->priv;

    elf_version(EV_CURRENT);

    /*
     * First, just open the file and do some sanity checks.  If this
     * doesn't seem like an ELF file, throw an optional warning and
     * return.  If it is an ELF file and we can't read it, or we can't
     * handle the type, throw an error and return.
     */
    if ((bf->fd = open(bf->filename,0,O_RDONLY)) < 0) {
	vwarnopt(1,LA_DEBUG,LF_ELF,"open %s: %s\n",bf->filename,strerror(errno));
	goto errout;
    }
    else if (!(bfelf->elf = elf_begin(bf->fd,ELF_C_READ,NULL))) {
	vwarnopt(1,LA_DEBUG,LF_ELF,"elf_begin %s: %s\n",
		 bf->filename,elf_errmsg(elf_errno()));
	goto errout;
    }
    else if (!gelf_getehdr(bfelf->elf,&bfelf->ehdr)) {
	verror("cannot read ELF header: %s",elf_errmsg(-1));
	errno = EINVAL;
	goto errout;
    }
    else if (bfelf->ehdr.e_type != ET_EXEC && bfelf->ehdr.e_type != ET_REL
	     && bfelf->ehdr.e_type != ET_DYN) {
	verror("unreadable ELF type 0x%x\n",bfelf->ehdr.e_type);
	errno = EINVAL;
	goto errout;
    }

    if (elf_get_arch_info(bfelf->elf,&bf->wordsize,&bf->endian)) {
	verror("could not get arch info!\n");
	goto errout;
    }

    if (bfelf->ehdr.e_type == ET_EXEC)
	bf->type = BINFILE_TYPE_EXEC;
    else if (bfelf->ehdr.e_type == ET_DYN)
	bf->type = BINFILE_TYPE_DYN;
    else if (bfelf->ehdr.e_type == ET_REL)
	bf->type = BINFILE_TYPE_REL;

    /*
     * Load all the ELF metadata we are going to save.
     */
    bfelf->ebl = ebl_openbackend(bfelf->elf);
    if (bfelf->ebl == NULL) {
	verror("cannot create EBL handle: %s",strerror(errno));
	goto errout;
    }

    bfelf->class = gelf_getclass(bfelf->elf);

#if _INT_ELFUTILS_VERSION >= 152
    if (elf_getshdrstrndx(bfelf->elf,&bfelf->shstrndx) < 0) {
#else 
    if (elf_getshstrndx(bfelf->elf,&bfelf->shstrndx) < 0) {
#endif
	verror("cannot get section header string table index\n");
	goto errout;
    }

    /*
     * Before we use elfutils calls that save pointers into the file or
     * data gleaned from it, we need to perform relocations if we have @bfinst.
     */
    if (bfelf->ehdr.e_type == ET_REL && bfinst) {
	/* Save the instance! */
	bf->instance = bfinst;

	/*
	 * Leave the ELF fd intact, and buffer the file into a memory
	 * buffer for relocation.
	 */
	if (stat(bf->filename,&stbuf)) {
	    verror("stat %s (before relocation): %s\n",
		   bf->filename,strerror(errno));
	    goto errout;
	}
	rci = 0;
	bf->image = malloc(stbuf.st_size);
	fdi = dup(bf->fd);
	lseek(fdi,0,SEEK_SET);
	while (rci < stbuf.st_size) {
	    rc = read(fdi,bf->image+rci,stbuf.st_size - rci);
	    if (rc < 0) {
		if (errno == EAGAIN || errno == EINTR)
		    continue;
		else {
		    verror("read(%s): %s\n",bf->filename,strerror(errno));
		    goto errout;
		}
	    }
	    rci += rc;
	}
	close(fdi);

	/*
	 * Now, while we still have the old ELF descriptor open, go
	 * through all the sections and apply relocations *in the memory
	 * image* we just read.
	 */
	vdebug(3,LA_DEBUG,LF_ELF,
	       "relocating ELF file %s in memory...\n",bf->filename);

	/* 
	 * Now load all the section headers and build up a tmp array.
	 */
	bfelf->shdrs = (GElf_Shdr *)calloc(bfelf->ehdr.e_shnum,sizeof(GElf_Shdr));
	if (bfelfinst->shdrs) {
	    memcpy(bfelf->shdrs,bfelfinst->shdrs,
		   bfelf->ehdr.e_shnum*sizeof(GElf_Shdr));
	}
	else {
	    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
		scn = elf_getscn(bfelf->elf,i);
		if (!gelf_getshdr(scn,&bfelf->shdrs[i])) {
		    verror("could not load section header for section %d!\n",i);
		    goto errout;
		}
	    }
	}

	for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	    shdr = &bfelf->shdrs[i];
	    scn = elf_getscn(bfelf->elf,i);
	    if (!scn) {
		verror("could not find Elf section for section %d!\n",i);
		continue;
	    }
	    else if (!shdr || shdr->sh_size <= 0) 
		continue;
	    else if (shdr->sh_type != SHT_REL)
		continue;

	    edata = elf_getdata(scn,NULL);
	    if (!edata || !edata->d_size || !edata->d_buf) {
		verror("cannot get data for relocation section %d during"
		       " relocation!\n",
		       i);
		continue;
	    }

	    /*
	     * Do the relocs.
	     */
	    nrels = shdr->sh_size / shdr->sh_entsize;

	    rsec = shdr->sh_info;
	    rstsec = shdr->sh_link;

	    /*
	     * Grab the symtab section referred to so we can load the syms.
	     */
	    rstscn = elf_getscn(bfelf->elf,rstsec);
	    if (!rstscn) {
		verror("could not load symtab section %d during relocation!\n",
		       rstsec);
		continue;
	    }
	    rstedata = elf_getdata(rstscn,NULL);
	    if (!rstedata || !rstedata->d_size || !rstedata->d_buf) {
		verror("cannot get data for valid symtab section %d during"
		       " relocation!\n",
		       rstsec);
		continue;
	    }

	    vdebug(3,LA_DEBUG,LF_ELF,
		   "found %d relocations in %d in ELF file %s\n",
		   nrels,i,bf->filename);

	    /*
	     * Don't realloc sections that are not getting loaded; we
	     * are not a linker that needs to recombine sections.
	     */
	    if (!(bfelf->shdrs[rsec].sh_flags & SHF_ALLOC)) {
		vdebug(3,LA_DEBUG,LF_ELF,
		       "skipping reloc section %d for non-alloc section %d\n",
		       i,rsec);
		continue;
	    }

	    for (j = 0; j < nrels; ++j) {
		if (!gelf_getrel(edata,j,&rel)) {
		    verror("bad relocation %d in %d; skipping!\n",j,i);
		    continue;
		}
		rtype = GELF_R_TYPE(rel.r_info);
		rsymidx = GELF_R_SYM(rel.r_info);
		if (!gelf_getsym(rstedata,rsymidx,&rsym)) {
		    verror("could not load sym %d in %d (for %d/%d) during"
			   " relocation; skipping!\n",
			   rsymidx,rstsec,j,i);
		    continue;
		}

		if (rsym.st_shndx >= bfelfinst->num_sections) {
		    verror("bad section %d for symbol %d (relocation %d/%d)!\n",
			   rsym.st_shndx,rsymidx,j,i);
		    continue;
		}

		/*
		 * The bit of mem we're going to modify is the offset in
		 * the ELF file of the section we're relocating, plus
		 * the r_offset in the relocation.
		 */
		rcoffset = bfelf->shdrs[rsec].sh_offset + rel.r_offset;

		if (GELF_ST_TYPE(rsym.st_info) == STT_SECTION) {
		    /*
		     * Don't realloc sections that are not getting
		     * loaded; we are not a linker that needs to
		     * recombine sections.
		     */
		    if (!(bfelf->shdrs[rsym.st_shndx].sh_flags & SHF_ALLOC)) {
			vdebug(20,LA_DEBUG,LF_ELF,
			       "skipping reloc for non-alloc section %d\n",
			       rsym.st_shndx);
			continue;
		    }

		    rvalue = (GElf_Addr)bfelfinst->section_tab[rsym.st_shndx];
		}
		else if (GELF_ST_TYPE(rsym.st_info) == STT_OBJECT
			 || GELF_ST_TYPE(rsym.st_info) == STT_FUNC) {
		    rvalue = rsym.st_value \
			+ (GElf_Addr)bfelfinst->section_tab[rsym.st_shndx];
		}
		else if (GELF_ST_TYPE(rsym.st_info) == STT_NOTYPE
			 && GELF_ST_BIND(rsym.st_info) == STB_GLOBAL) {
		    vdebug(6,LA_DEBUG,LF_ELF,
			   "skipping global symbol %d"
			   " (relocation %d/%d); skipping!\n",
			   rsymidx,j,i);
		}
		else {
		    verror("unknown symbol type %d for symbol %d"
			   " (relocation %d/%d); skipping!\n",
			   GELF_ST_TYPE(rsym.st_info),rsymidx,j,i);
		    continue;
		}

		switch (rtype) {
		case R_386_32:
		    /* Sv + Ad */
		    if (rcoffset >= stbuf.st_size)  {
			vdebug(5,LA_DEBUG,LF_ELF,
				 "relocation offset exceeds file length by %d"
				 " (symbol %d, relocation %d/%d); skipping\n!",
				 rcoffset - stbuf.st_size,
				 rsymidx,j,i);
			continue;
		    }
		    memcpy(bf->image+rcoffset,&rvalue,bf->wordsize);
		    break;
		case R_386_PC32:
		    /* Sv + Ad - P (r_offset?) */
		    rvalue -= rel.r_offset;
		    if (rcoffset >= stbuf.st_size)  {
			vdebug(5,LA_DEBUG,LF_ELF,
				 "relocation offset exceeds file length by %d"
				 " (symbol %d, relocation %d/%d); skipping\n!",
				 rcoffset - stbuf.st_size,
				 rsymidx,j,i);
			continue;
		    }
		    memcpy(bf->image+rcoffset,&rvalue,bf->wordsize);
		    break;
		default:
		    verror("cannot handle relocation type %d for symbol %d"
			   " (relocation %d/%d); skipping\n!",
			   rtype,rsymidx,j,i);
		    break;
		}
	    }
	}

	free(bfelf->shdrs);

	/*
	 * Now, close off the old ELF and its fd, and open the new ELF
	 * against the memory image.
	 */
	elf_end(bfelf->elf);
	close(bf->fd);
	bf->fd = -1;
	bfelf->elf = elf_memory(bf->image,stbuf.st_size);

	/*
	 * Also, update sh_flags from the instance's headers if they
	 * exist.
	 */
	if (bfelfinst->shdrs) {
	    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
		scn = elf_getscn(bfelf->elf,i);
		if (!(shdr_new = gelf_getshdr(scn,&shdr_new_mem))) {
		    verror("could not load section header for section %d!\n",i);
		    goto errout;
		}

		shdr_new->sh_flags = bfelfinst->shdrs[i].sh_flags;

		if (gelf_update_shdr(scn,shdr_new)) {
		    vwarnopt(3,LA_DEBUG,LF_ELF,
			     "could not update sh_flags for section %d; skipping"
			     " but debuginfo reloc might be broken!\n",i);
		    continue;
		}
	    }
	}

	vdebug(3,LA_DEBUG,LF_ELF,
	       "opened relocated ELF file %s in memory\n",bf->filename);
    }
    else if (bfelf->ehdr.e_type == ET_REL) {
	vwarnopt(2,LA_DEBUG,LF_ELF,
		 "relocatable file %s, but no program image; not relocating!\n",
		 bf->filename);
    }

    /*
     * Save off the program headers, and calculate the base addrs.
     * 
     * Search through all the program headers; for those of type LOAD,
     * find the minimum phys addr (and its corresponding virt addr);
     * take these addrs to be used in calculating the phys_offset later
     * for use in virt<->phys addr translation from debuginfo virt addrs
     * to phys machine addrs.
     */
    if (bfelf->ehdr.e_phnum > 0) {
	bfelf->phdrs = (GElf_Phdr *)calloc(bfelf->ehdr.e_phnum,sizeof(GElf_Phdr));
	bf->base_phys_addr = ADDRMAX;
	bf->base_virt_addr = ADDRMAX;

	for (i = 0; i < bfelf->ehdr.e_phnum; ++i) {
	    if (!(phdr = gelf_getphdr(bfelf->elf,i,&bfelf->phdrs[i]))) {
		vwarn("could not read program header %d\n",(int)i);
		continue;
	    }

	    if (phdr->p_type != PT_LOAD)
		continue;

	    if (phdr->p_vaddr < bf->base_virt_addr) {
		bf->base_phys_addr = phdr->p_paddr;
		bf->base_virt_addr = phdr->p_vaddr;
	    }
	}

	/*
	 * If we didn't find anything (weird), make sure to use 0 as our
	 * base; it's the best we can do, realistically.
	 */
	if (bf->base_phys_addr == ADDRMAX && bf->base_virt_addr == ADDRMAX) 
	    bf->base_phys_addr = bf->base_virt_addr = 0;
    }

    /* 
     * Now load all the section headers and build up a simple array.
     */
    bfelf->shdrs = (GElf_Shdr *)calloc(bfelf->ehdr.e_shnum,sizeof(GElf_Shdr));
    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	scn = elf_getscn(bfelf->elf,i);
	if (!gelf_getshdr(scn,&bfelf->shdrs[i])) {
	    verror("could not load section header for section %d!\n",i);
	    goto errout;
	}
    }

    /* Scan for various sections. */
    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	shdr = &bfelf->shdrs[i];
	scn = elf_getscn(bfelf->elf,i);

	if (!shdr || shdr->sh_size <= 0) 
	    continue;
	if (!scn) {
	    verror("could not find Elf section for section %d!\n",i);
	    continue;
	}

	name = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	if (shdr->sh_type == SHT_STRTAB && strcmp(name,".strtab") == 0) {
	    if (bf->strtab) {
		vwarn("multiple .strtab sections; ignoring after first!\n");
		continue;
	    }

	    vdebug(2,LA_DEBUG,LF_ELF,
		   "found .strtab section in ELF file %s\n",
		   bf->filename);

	    edata = elf_rawdata(scn,NULL);
	    if (!edata || !edata->d_size || !edata->d_buf) {
		verror("cannot get data for valid section %s in %s: %s",
		       name,bf->filename,elf_errmsg(-1));
		goto errout;
	    }

	    strtabsec = i;
	    bf->strtablen = edata->d_size;
	    bf->strtab = malloc(edata->d_size);
	    memcpy(bf->strtab,edata->d_buf,edata->d_size);
	}
	else if (shdr->sh_type == SHT_SYMTAB) {
	    if (symtabsec > -1) {
		vwarn("multiple .dynsym sections; ignoring after first!\n");
		continue;
	    }

	    vdebug(2,LA_DEBUG,LF_ELF,
		   "found %s section in ELF file %s\n",name,bf->filename);

	    symtabsec = i;
	}
	else if (shdr->sh_type == SHT_DYNSYM) {
	    if (dynsymtabsec > -1) {
		vwarn("multiple .dynsym sections; ignoring after first!\n");
		continue;
	    }

	    vdebug(2,LA_DEBUG,LF_ELF,
		   "found %s section in ELF file %s\n",name,bf->filename);

	    dynsymtabsec = i;

	    /*
	     * Find the strtab for it.
	     */
	    dynstrtabsec = shdr->sh_link;
	    if (dynstrtabsec >= bfelf->ehdr.e_shnum || dynstrtabsec < 1) {
		verror("bad sh_link (dynstr sec idx) %d; not using dynsym sec %d!\n",
		       dynstrtabsec,dynsymtabsec);
		dynsymtabsec = -1;
		dynstrtabsec = -1;
	    }

	    scn = elf_getscn(bfelf->elf,dynstrtabsec);
	    if (!scn) {
		verror("could not find Elf section for section %d!\n",i);
		dynsymtabsec = -1;
		dynstrtabsec = -1;
		continue;
	    }
	    edata = elf_rawdata(scn,NULL);
	    if (!edata || !edata->d_size || !edata->d_buf) {
		verror("cannot get data for valid section %s in %s: %s",
		       name,bf->filename,elf_errmsg(-1));
		goto errout;
	    }

	    bf->dynstrtablen = edata->d_size;
	    bf->dynstrtab = malloc(edata->d_size);
	    memcpy(bf->dynstrtab,edata->d_buf,edata->d_size);
	}
	else if (strcmp(name,".plt") == 0) {
	    vdebug(2,LA_DEBUG,LF_ELF,
		   "found %s section (%d); recording\n",
		   name,shdr->sh_size);
	    has_plt = 1;
	    /* Important if we process .rela.plt */
	    plt_entry_size = shdr->sh_entsize;
	    plt_start = shdr->sh_addr;
	    plt_size = shdr->sh_size;
	}
	else if (strcmp(name,".dynamic") == 0) {
	    vdebug(2,LA_DEBUG,LF_ELF,
		   "found %s section (%d); ELF file is dynamic\n",
		   name,shdr->sh_size);
	    bf->is_dynamic = 1;
	}
	else if (strcmp(name,".debug_info") == 0) {
	    vdebug(2,LA_DEBUG,LF_DFILE,
		   "found %s section (%d)\n",name,shdr->sh_size);
	    bf->has_debuginfo = 1;
	}
	else if (!bfelf->buildid && shdr->sh_type == SHT_NOTE) {
	    vdebug(2,LA_DEBUG,LF_DFILE,
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
		if (bf->wordsize == 8) {
		    nthdr64 = (Elf64_Nhdr *)ndata;
		    /* skip past the header and the name string and its
		     * padding */
		    ndata += sizeof(Elf64_Nhdr);
		    vdebug(5,LA_DEBUG,LF_DFILE,"found note name '%s'\n",ndata);
		    ndata += nthdr64->n_namesz;
		    if (nthdr64->n_namesz % 4)
			ndata += (4 - nthdr64->n_namesz % 4);
		    vdebug(5,LA_DEBUG,LF_DFILE,"found note desc '%s'\n",ndata);
		    /* dig out the build ID */
		    if (nthdr64->n_type == NT_GNU_BUILD_ID) {
			bfelf->buildid = strdup(ndata);
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
			bfelf->buildid = strdup(ndata);
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
	    bfelf->gnu_debuglinkfile = strdup(edata->d_buf);
	    bfelf->gnu_debuglinkfile_crc = \
		*(uint32_t *)(edata->d_buf + edata->d_size - 4);
	}
    }
    if (!bf->is_dynamic)
	vdebug(2,LA_DEBUG,LF_ELF,"ELF file is static\n");

    /*
     * Infer symbol names in the PLT if there was one by processing the
     * relocations for the PLT; those have the symbol names; we generate
     * a symbol for each JMP_SLOT relocation, assuming that the GOT and
     * PLT are strictly ordered w.r.t. one another, and assuming that a
     * PLT has a single "header" entry at its top.
     */
    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	shdr = &bfelf->shdrs[i];
	scn = elf_getscn(bfelf->elf,i);

	if (!shdr || shdr->sh_size <= 0) 
	    continue;
	if (!scn) {
	    verror("could not find Elf section for section %d!\n",i);
	    continue;
	}

	name = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	if (shdr->sh_type != SHT_RELA || strcmp(name,".rela.plt") != 0) 
	    continue;

	if (!has_plt) {
	    verror("found .rela.plt section, but no .plt in ELF file %s!\n",
		   bf->filename);
	    break;
	}

	vdebug(2,LA_DEBUG,LF_ELF,
	       "found .rela.plt section in ELF file %s;"
	       " generating @plt symbol names\n",
	       bf->filename);

	edata = elf_rawdata(scn,NULL);
	if (!edata || !edata->d_size || !edata->d_buf) {
	    verror("cannot get data for valid section %s in %s: %s",
		   name,bf->filename,elf_errmsg(-1));
	    goto errout;
	}

	/*
	 * Process only the JMP_SLOT relocs.
	 */
	nrels = shdr->sh_size / shdr->sh_entsize;

	rsec = shdr->sh_info;
	rstsec = shdr->sh_link;

	rstrsec = bfelf->shdrs[rstsec].sh_link;

	/*
	 * Grab the symtab section referred to so we can load the syms.
	 */
	rstscn = elf_getscn(bfelf->elf,rstsec);
	if (!rstscn) {
	    verror("could not load symtab section %d during plt relocation!\n",
		   rstsec);
	    break;
	}
	rstedata = elf_getdata(rstscn,NULL);
	if (!rstedata || !rstedata->d_size || !rstedata->d_buf) {
	    verror("cannot get data for valid symtab section %d during"
		   " plt relocation!\n",
		       rstsec);
	    break;
	}

	vdebug(3,LA_DEBUG,LF_ELF,
	       "found %d plt relocations in %d in ELF file %s\n",
	       nrels,i,bf->filename);

	/* Skip the first plt "header" entry. */
	plt_idx = 1;

	for (j = 0; j < nrels; ++j) {
	    if (!gelf_getrela(edata,j,&rela)) {
		verror("bad relocation %d in %d; skipping!\n",j,i);
		continue;
	    }
	    rtype = GELF_R_TYPE(rela.r_info);
	    rsymidx = GELF_R_SYM(rela.r_info);
	    if (!gelf_getsym(rstedata,rsymidx,&rsym)) {
		verror("could not load sym %d in %d (for %d/%d) during"
		       " relocation; skipping!\n",
		       rsymidx,rstsec,j,i);
		continue;
	    }

	    if (rtype != R_X86_64_JUMP_SLOT || rtype != R_386_JMP_SLOT) {
		verror("unexpected relocation type %d (not JMP_SLOT) in"
		       " .rela.plt at idx %d; plt index names may be wrong!\n",
		       rtype,j);
		continue;
	    }


	    symname = elf_strptr(bfelf->elf,rstrsec,rsym.st_name);
	    if (!symname) {
		vwarn("skipping .rela.plt ELF symbol at .rela.plt idx %d;"
		      " bad symbol strtab idx %d\n",
		      j,(int)rsym.st_name);
		continue;
	    }

	    len = strlen(symname) + sizeof("@plt") + 1;
	    pltsymbuf = calloc(len,sizeof(char));
	    snprintf(pltsymbuf,len,"%s@plt",symname);

	    symbol = symbol_create(bf->symtab,
				   (SMOFFSET)(shdr->sh_addr + j * shdr->sh_entsize),
				   pltsymbuf,0,SYMBOL_TYPE_FUNCTION,
				   SYMBOL_SOURCE_ELF,0);
	    RHOLD(symbol,bf);

	    if (GELF_ST_BIND(rsym.st_info) == STB_GLOBAL
		|| GELF_ST_BIND(rsym.st_info) == STB_WEAK)
		symbol->isexternal = 1;

	    symbol->size.bytes = plt_entry_size;
	    symbol->size_is_bytes = 1;

	    symbol->base_addr = (ADDR)(plt_start + plt_idx * plt_entry_size);
	    symbol->has_base_addr = 1;

	    symtab_insert(bf->symtab,symbol,0);

	    clrange_add(&bf->ranges,symbol->base_addr,
			symbol->base_addr + symbol->size.bytes,symbol);

	    vdebug(3,LA_DEBUG,LF_ELF,
		   "added plt index ELF symbol %s at 0x%"PRIxADDR"\n",
		   symbol->name,symbol->base_addr);

	    ++plt_idx;
	}

	break;
    }

    /*
     * Now process symtab section.  If we have an instance, grab the
     * symbol locations out of that symtab.
     */
    if (symtabsec > -1) {
	shdr = &bfelf->shdrs[symtabsec];

	name = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	vdebug(2,LA_DEBUG,LF_ELF,"processing %s section in ELF file %s\n",
	       name,bf->filename);

	scn = elf_getscn(bfelf->elf,symtabsec);
	edata = elf_getdata(scn,NULL);
	if (!edata || !edata->d_size || !edata->d_buf) {
	    verror("cannot get data for valid section %s in %s: %s",
		   name,bf->filename,elf_errmsg(-1));
	    goto errout;
	}

	bfelf->num_symbols = \
	    edata->d_size / (bfelf->class == ELFCLASS32 ? sizeof (Elf32_Sym) \
			                                : sizeof (Elf64_Sym));

	vdebug(2,LA_DEBUG,LF_ELF,
	       "%s section in ELF file %s has %d symbols\n",
	       name,bf->filename,bfelf->num_symbols);

	/* Load the symtab */
	for (ii = 0; ii < bfelf->num_symbols; ++ii) {
	    sym = gelf_getsym(edata,ii,&sym_mem);
	    if (sym->st_name >= bf->strtablen) {
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
	    if (stt == STT_NOTYPE && sym->st_shndx < bfelf->ehdr.e_shnum) {
		if (bfelf->shdrs[sym->st_shndx].sh_flags & SHF_EXECINSTR)
		    stt = STT_FUNC;
		else if (bfelf->shdrs[sym->st_shndx].sh_flags & SHF_ALLOC)
		    stt = STT_OBJECT;
	    }

	    if (!(stt == STT_OBJECT || stt == STT_COMMON || stt == STT_TLS
		  || stt == STT_FUNC
#if defined(STT_GNU_IFUNC)
		  || stt == STT_GNU_IFUNC
#endif
		  )) 
		/* Skip all non-code symbols */
		continue;

	    /*
	     * If it is not in a section in our binary, don't save it.
	     * XXX: we could expose this as an option, BUT since we're
	     * not a linker we don't really care.
	     */
	    if (sym->st_shndx == SHN_UNDEF)
		continue;

	    /*
	     * Don't want various meaningless symbols...
	     */
	    if (sym->st_shndx == SHN_ABS && stt == STT_OBJECT && sym->st_value == 0)
		continue;

	    /*
	     * Either way, don't have symbol_create copy symname; we do
	     * it here if we need to.
	     */
#ifdef DWDEBUG_NOUSE_STRTAB
	    symname = strdup(&bf->strtab[sym->st_name]);
#else
	    symname = &bf->strtab[sym->st_name];
#endif

	    symbol = symbol_create(bf->symtab,(SMOFFSET)ii,symname,0,
				   (stt == STT_OBJECT || stt == STT_TLS
				    || stt == STT_COMMON)	\
				   ? SYMBOL_TYPE_VAR : SYMBOL_TYPE_FUNCTION,
				   SYMBOL_SOURCE_ELF,0);
	    RHOLD(symbol,bf);

	    if (GELF_ST_BIND(sym->st_info) == STB_GLOBAL
		|| GELF_ST_BIND(sym->st_info) == STB_WEAK)
		symbol->isexternal = 1;

	    symbol->size.bytes = sym->st_size;
	    symbol->size_is_bytes = 1;

	    if (bfelfinst && bfelfinst->symbol_tab && ii < bfelfinst->num_symbols)
		symbol->base_addr = bfelfinst->symbol_tab[ii];
	    else
		symbol->base_addr = (ADDR)sym->st_value;
	    symbol->has_base_addr = 1;

	    symtab_insert(bf->symtab,symbol,0);

	    /*
	     * Insert into debugfile->addresses IF the hashtable is
	     * empty (i.e., if we load the symtab first, before the
	     * debuginfo file), or if there is not anything already
	     * at this location.  We want debuginfo symbols to trump
	     * ELF symbols in this table.
	     */
	    /* XXXXXX
	    if (g_hash_table_size(debugfile->addresses) == 0
		|| !g_hash_table_lookup(debugfile->addresses,
					(gpointer)symbol->base_addr))
		g_hash_table_insert(debugfile->addresses,
				    (gpointer)symbol->base_addr,
				    (gpointer)symbol);
	    */

	    if (symbol->base_addr != 0)
		clrange_add(&bf->ranges,symbol->base_addr,
			    symbol->base_addr + symbol->size.bytes,symbol);
	}
    }

    /*
     * Now process dynsymtab section.  Differences from above code:
     * don't duplicate symbols (i.e., if symtab had one with same name
     * and addr, don't duplicate it); and don't check bf inst (XXX must
     * reconsider how that fits with dynsyms, not just "regular" syms).
     */
    if (dynsymtabsec > -1) {
	shdr = &bfelf->shdrs[dynsymtabsec];

	name = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);
	vdebug(2,LA_DEBUG,LF_ELF,"processing %s section in ELF file %s\n",
	       name,bf->filename);

	scn = elf_getscn(bfelf->elf,dynsymtabsec);
	edata = elf_getdata(scn,NULL);
	if (!edata || !edata->d_size || !edata->d_buf) {
	    verror("cannot get data for valid section %s in %s: %s",
		   name,bf->filename,elf_errmsg(-1));
	    goto errout;
	}

	bfelf->num_symbols = \
	    edata->d_size / (bfelf->class == ELFCLASS32 ? sizeof (Elf32_Sym) \
			                                : sizeof (Elf64_Sym));
	vdebug(2,LA_DEBUG,LF_ELF,
	       "%s section in ELF file %s has %d symbols\n",
	       name,bf->filename,bfelf->num_symbols);

	/* Load the symtab */
	for (ii = 0; ii < bfelf->num_symbols; ++ii) {
	    sym = gelf_getsym(edata,ii,&sym_mem);
	    if (sym->st_name >= bf->dynstrtablen) {
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
	    if (stt == STT_NOTYPE && sym->st_shndx < bfelf->ehdr.e_shnum) {
		if (bfelf->shdrs[sym->st_shndx].sh_flags & SHF_EXECINSTR)
		    stt = STT_FUNC;
		else if (bfelf->shdrs[sym->st_shndx].sh_flags & SHF_ALLOC)
		    stt = STT_OBJECT;
	    }

	    if (!(stt == STT_OBJECT || stt == STT_COMMON || stt == STT_TLS
		  || stt == STT_FUNC
#if defined(STT_GNU_IFUNC)
		  || stt == STT_GNU_IFUNC
#endif
		  )) 
		/* Skip all non-code symbols */
		continue;

	    /*
	     * If it is not in a section in our binary, don't save it.
	     * XXX: we could expose this as an option, BUT since we're
	     * not a linker we don't really care.
	     */
	    if (sym->st_shndx == SHN_UNDEF)
		continue;

	    /*
	     * Don't want various meaningless symbols...
	     */
	    if (sym->st_shndx == SHN_ABS && stt == STT_OBJECT && sym->st_value == 0)
		continue;

	    /*
	     * Check symtab; don't duplicate!
	     */
	    if ((tsymbol = symtab_get_sym(bf->symtab,&bf->dynstrtab[sym->st_name]))
		&& tsymbol->base_addr == sym->st_value) {
		vdebug(5,LA_DEBUG,LF_ELF,
		       "not creating duplicate dynsym %s (0x%"PRIxADDR")\n",
		       tsymbol->name,tsymbol->base_addr);
		continue;
	    }

	    /*
	     * Either way, don't have symbol_create copy symname; we do
	     * it here if we need to.
	     */
#ifdef DWDEBUG_NOUSE_STRTAB
	    symname = strdup(&bf->dynstrtab[sym->st_name]);
#else
	    symname = &bf->dynstrtab[sym->st_name];
#endif

	    symbol = symbol_create(bf->symtab,(SMOFFSET)ii,symname,0,
				   (stt == STT_OBJECT || stt == STT_TLS
				    || stt == STT_COMMON)	\
				   ? SYMBOL_TYPE_VAR : SYMBOL_TYPE_FUNCTION,
				   SYMBOL_SOURCE_ELF,0);
	    RHOLD(symbol,bf);

	    if (GELF_ST_BIND(sym->st_info) == STB_GLOBAL
		|| GELF_ST_BIND(sym->st_info) == STB_WEAK)
		symbol->isexternal = 1;

	    symbol->size.bytes = sym->st_size;
	    symbol->size_is_bytes = 1;

	    if (sym->st_value > 0) {
		symbol->base_addr = (ADDR)sym->st_value;
		symbol->has_base_addr = 1;
	    }

	    symtab_insert(bf->symtab,symbol,0);

	    /*
	     * Insert into debugfile->addresses IF the hashtable is
	     * empty (i.e., if we load the symtab first, before the
	     * debuginfo file), or if there is not anything already
	     * at this location.  We want debuginfo symbols to trump
	     * ELF symbols in this table.
	     */
	    /* XXXXXX
	    if (g_hash_table_size(debugfile->addresses) == 0
		|| !g_hash_table_lookup(debugfile->addresses,
					(gpointer)symbol->base_addr))
		g_hash_table_insert(debugfile->addresses,
				    (gpointer)symbol->base_addr,
				    (gpointer)symbol);
	    */

	    if (symbol->base_addr != 0)
		clrange_add(&bf->ranges,symbol->base_addr,
			    symbol->base_addr + symbol->size.bytes,symbol);
	}
    }

    {
	/* Now, go through all the address ranges and update their sizes 
	 * based on the following range's address -- this is
	 * definitely possibly wrong sometimes.  Could be wrong!
	 *
	 * The idea is, for any 0-length isexternal (GLOBAL ELF sym)
	 * function symbol, don't just look for the next symbol; look
	 * for the next global function symbol (or end of section).
	 *
	 * (This strategy is informed by how the Linux kernel does
	 * its i386 asm files; "functions" are declared global;
	 * labels are not, so they appear as LOCAL ELF symbols.)
	 *
	 * This will hopefully will allow disassembly of non-DWARF
	 * functions -- since we guess their length here.  Could be
	 * wrong sometimes.
	 */
	nextstart = 0;
	ral = clrange_find_next_inc(&bf->ranges,nextstart);
	while (ral) {
	    /*
	     * Go through each crd (symbol + metadata) at this start
	     * address, and if the CRD is 0-length, try to find the next
	     * symbol.
	     *
	     * One optimization (maybe) we *chould* do is if any symbols
	     * on the list are nonzero-length, just make the symbols
	     * that are 0-length be the value of the nonzero length, if
	     * their attributes match.
	     */
	    for (j = 0; j < array_list_len(ral); ++j) {
		crd = (struct clf_range_data *)array_list_item(ral,j);
		symbol = (struct symbol *)CLRANGE_DATA(crd);
		/* Doesn't matter which crd we take the next start value
		 * from; they are all the same.
		 */
		nextstart = start = CLRANGE_START(crd);
		end = CLRANGE_END(crd);

		if (start != end) 
		    continue;

		vdebug(16,LA_DEBUG,LF_ELF,
		       "checking end of ELF symbol %s (0x%"PRIxADDR","
		       "0x%"PRIxADDR")\n",
		       symbol_get_name(symbol),
		       CLRANGE_START(crd),CLRANGE_END(crd));

		/*
		 * Find the next nearest start range, such that
		 * attributes match.
		 *
		 * If the 0-length *function* symbol is global, and the
		 * next symbol is NOT global, we need to try to find the
		 * next global symbol!
		 */
		if (SYMBOL_IS_FUNCTION(symbol) && symbol->isexternal) {
		    gcrd = NULL;
		    tmpstart = start;
		    while ((tmp_ral = \
			    clrange_find_next_exc(&bf->ranges,
						  tmpstart))) {
			/* Need to find *any* global symbol at this ral,
			 * so check the whole list!
			 */
			for (k = 0; k < array_list_len(tmp_ral); ++k) {
			    tmp_crd = (struct clf_range_data *)	\
				array_list_item(tmp_ral,k);
			    tmp_symbol = (struct symbol *)CLRANGE_DATA(tmp_crd);
			    if (tmp_symbol->isexternal) {
				gcrd = tmp_crd;
				break;
			    }

			    /* Doesn't matter which one; all same. */
			    tmpstart = CLRANGE_START(tmp_crd);
			}

			if (gcrd)
			    break;
		    }

		    /*
		     * We need to find the section containing the base
		     * addr, and make sure whatever next addr we found,
		     * if any, is still in that section!  If it is not
		     * still in that section (or if we didn't find one),
		     * use the section end addr.
		     */
		    sec_found = 0;
		    sec_end = 0;
		    for (ii = 0; ii < bfelf->ehdr.e_shnum; ++ii) {
			if (start >= bfelf->shdrs[ii].sh_addr
			    && start < (bfelf->shdrs[ii].sh_addr 
					 + bfelf->shdrs[ii].sh_size)) {
			    sec_found = 1;
			    sec_end = bfelf->shdrs[ii].sh_addr 
				+ bfelf->shdrs[ii].sh_size;
			    break;
			}
		    }

		    if (!sec_found) {
			vwarn("could not find section containing 0x%"PRIxADDR";"
			      " not updating 0-length GLOBAL %s!\n",
			      start,symbol_get_name(symbol));
			goto lcontinue;
		    }
	
		    if (!gcrd || CLRANGE_START(gcrd) > sec_end) {
			if (!gcrd) {
			    vdebug(2,LA_DEBUG,LF_ELF,
				   "could not find next global symbol after %s;"
				   " using section(%d:%d) end 0x%"PRIxADDR"!\n",
				   ii,bfelf->shdrs[ii].sh_size,
				   symbol_get_name(symbol),sec_end);
			}
			else {
			    vdebug(2,LA_DEBUG,LF_ELF,
				   "next global symbol after %s was past section"
				   "(%d:%d); using section end 0x%"PRIxADDR"!\n",
				   symbol_get_name(symbol),
				   ii,bfelf->shdrs[ii].sh_size,sec_end);
			}

			clrange_update_end(&bf->ranges,start,sec_end,symbol);

			symbol->size.bytes = sec_end - start;
			symbol->size_is_bytes = 1;
			symbol->guessed_size = 1;
		    }
		    else {
			vdebug(2,LA_DEBUG,LF_ELF,
			       "updating 0-length GLOBAL symbol %s to"
			       " 0x%"PRIxADDR",0x%"PRIxADDR"\n",
			       symbol_get_name(symbol),start,CLRANGE_START(gcrd));
		    
			clrange_update_end(&bf->ranges,start,
					   CLRANGE_START(gcrd),symbol);

			symbol->size.bytes = CLRANGE_START(gcrd) - start;
			symbol->size_is_bytes = 1;
			symbol->guessed_size = 1;
		    }
		}
		else {
		    tmp_ral = clrange_find_next_exc(&bf->ranges,start);
		    if (!tmp_ral) {
			vwarnopt(9,LA_DEBUG,LF_ELF,
				 "could not find a next range after %s;"
				 " not updating 0-length symbol!\n",
				 symbol_get_name(symbol));
			goto lcontinue;
		    }

		    /* Just take the first one! */
		    gcrd = (struct clf_range_data *)array_list_item(tmp_ral,0);

		    /*
		     * We need to find the section containing the base
		     * addr, and make sure whatever next addr we found,
		     * if any, is still in that section!  If it is not
		     * still in that section (or if we didn't find one),
		     * use the section end addr.
		     */
		    sec_found = 0;
		    sec_end = 0;
		    for (ii = 0; ii < bfelf->ehdr.e_shnum; ++ii) {
			if (start >= bfelf->shdrs[ii].sh_addr
			    && start < (bfelf->shdrs[ii].sh_addr 
					 + bfelf->shdrs[ii].sh_size)) {
			    sec_found = 1;
			    sec_end = bfelf->shdrs[ii].sh_addr 
				+ bfelf->shdrs[ii].sh_size;
			    break;
			}
		    }

		    if (!sec_found) {
			vwarn("could not find section containing 0x%"PRIxADDR";"
			      " not updating 0-length GLOBAL %s!\n",
			      start,symbol_get_name(symbol));
			goto lcontinue;
		    }

		    if (CLRANGE_START(gcrd) > sec_end) {
			vdebug(2,LA_DEBUG,LF_ELF,
			       "next global symbol after %s was past section"
			       "(%d:%d); using section end 0x%"PRIxADDR"!\n",
			       symbol_get_name(symbol),
			       ii,bfelf->shdrs[ii].sh_size,sec_end);

			clrange_update_end(&bf->ranges,start,sec_end,symbol);

			symbol->size.bytes = sec_end - start;
			symbol->size_is_bytes = 1;
			symbol->guessed_size = 1;
		    }
		    else {

			vdebug(2,LA_DEBUG,LF_ELF,
			       "updating 0-length symbol %s to 0x%"PRIxADDR","
			       "0x%"PRIxADDR"\n",
			       symbol_get_name(symbol),start,CLRANGE_START(gcrd));

			clrange_update_end(&bf->ranges,start,
					   CLRANGE_START(gcrd),symbol);

			symbol->size.bytes = CLRANGE_START(gcrd) - start;
			symbol->size_is_bytes = 1;
			symbol->guessed_size = 1;
		    }
		}
	    }

	lcontinue:
	    ral = clrange_find_next_exc(&bf->ranges,nextstart);
	}
    }

    {
	/*
	 * NB: make a special header "function" symbol for the plt.
	 * This is helpful for stuff that wants to disasm the plt -- but
	 * at the moment we can't disasm for plain code blocks, only for
	 * symbols.
	 *
	 * We basically run the length of this symbol all the way to
	 * either the end of the PLT, or to the first symbol in the PLT.
	 */
	if (has_plt) {
	    symbol = symbol_create(bf->symtab,(SMOFFSET)0,strdup("_header@plt"),0,
				   SYMBOL_TYPE_FUNCTION,SYMBOL_SOURCE_ELF,0);
	    RHOLD(symbol,bf);

	    symbol->isexternal = 0;
	    symbol->size_is_bytes = 1;
	    symbol->base_addr = plt_start;
	    symbol->has_base_addr = 1;

	    ral = clrange_find_next_exc(&bf->ranges,plt_start);
	    if (!ral) {
		symbol->size.bytes = plt_size;
		vwarnopt(9,LA_DEBUG,LF_ELF,
			 "could not find a symbol following the PLT; assuming _header@plt is the whole PLT!\n");
	    }
	    else {
		/* Just take the first one! */
		gcrd = (struct clf_range_data *)array_list_item(ral,0);

		if (CLRANGE_START(gcrd) >= (plt_start + plt_size)) {
		    symbol->size.bytes = plt_size;
		    vwarnopt(9,LA_DEBUG,LF_ELF,
			     "could not find a symbol following the PLT within"
			     " the PLT; assuming _header@plt is the whole PLT!\n");
		}
		else {
		    symbol->size.bytes = CLRANGE_START(gcrd) - plt_start;
		    
		    vdebug(2,LA_DEBUG,LF_ELF,
			   "setting _header@plt size to %d bytes.\n",
			   symbol->size.bytes);
		}
	    }

	    symtab_insert(bf->symtab,symbol,0);

	    clrange_add(&bf->ranges,symbol->base_addr,
			symbol->base_addr + symbol->size.bytes,symbol);
	}
    }

#ifdef DWDEBUG_NOUSE_STRTAB
    /*
     * Only save elf_strtab if we're gonna use it.
     */
    if (bf->strtab) {
	free(bf->strtab);
	bf->strtablen = 0;
	bf->strtab = NULL;
    }
    if (bf->dynstrtab) {
	free(bf->dynstrtab);
	bf->dynstrtablen = 0;
	bf->dynstrtab = NULL;
    }
#endif

    return bf;

 errout:
    if (bf) {
	binfile_close(bf);
	binfile_free(bf,1);
    }
    else if (bfelf) {
	free(bfelf);
    }

    return NULL;
}

