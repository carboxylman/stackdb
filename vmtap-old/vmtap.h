#ifndef _VMTAP_H
#define _VMTAP_H

typedef int (*VMTAP_CALLBACK) (void *);

extern
int __register_vmtap(const char *domain,
                     const char *symbol, 
                     VMTAP_CALLBACK callback, 
                     void *prefunc,
                     void *postfunc);

extern
int loop_vmtap(void);

extern
void unregister_vmtap(void);

extern
const char *domain_name(void);

extern
unsigned int *domain_id(void);

extern
const char *symbol_name(void);

extern
unsigned long symbol_addr(void);

extern
unsigned long arg(int num);

extern
const char *read_path(unsigned long addr);

#endif /*_VMTAP_H */
