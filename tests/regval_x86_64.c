
int main(int argc,char **argv) {
    __asm__ ("mov $2, %rbx\n\t"
	     "mov $3, %rcx\n\t"
	     "mov $4, %rdx\n\t"
	     "mov $5, %rdi\n\t"
	     "mov $6, %rsi\n\t"
	     "mov $20, %r8\n\t"
	     "mov $21, %r9\n\t"
	     "mov $22, %r10\n\t"
	     "mov $23, %r11\n\t"
	     "mov $24, %r12\n\t"
	     "mov $25, %r13\n\t"
	     "mov $26, %r14\n\t"
	     "mov $27, %r15\n\t"
	     //"mov $10, %rax\n\t"
	     //"mov %ax, %ds\n\t"
	     //"mov $11, %rax\n\t"
	     //"mov %ax, %es\n\t"
	     //"mov $12, %rax\n\t"
	     //"mov %ax, %cs\n\t"
	     //"mov $13, %rax\n\t"
	     //"mov %ax, %fs\n\t"
	     //"mov $14, %rax\n\t"
	     //"mov %ax, %gs\n\t"
	     "mov $1, %rax\n\t"
	     );

    while (1)
	;

    return 0;
}
