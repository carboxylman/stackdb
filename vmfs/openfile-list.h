#ifndef _OPENFILE_LIST_H
#define _OPENFILE_LIST_H

#define OPT_COMMAND_WIDTH (5)

int predict_ksyms(char *ksyms, const char *sysmap);

int fill_parent_dir(char *buf,
                    uint32_t d_parent,
                    uint32_t d_parent_offset,
                    uint32_t d_name_offset,
                    uint32_t qlen_offset,
                    uint32_t qname_offset,
                    xa_instance_t *xai);

#endif /* OPENFILE_LIST_H */
