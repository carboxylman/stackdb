
int main(int argc,char **argv) {
    __asm__ ("movl $1, %eax\n\t"
	     "movl $2, %ebx\n\t"
	     "movl $3, %ecx\n\t"
	     "movl $4, %edx\n\t"
	     "movl $5, %edi\n\t"
	     "movl $6, %esi\n\t"
	     //"movl $10, %es\n\t"
	     //"movl $11, %ds\n\t"
	     //"movl $12, %ss\n\t"
	     );

    while (1)
	;

    return 0;
}
