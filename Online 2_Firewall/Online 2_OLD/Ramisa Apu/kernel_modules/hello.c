#include<linux/kernel.h>
#include<linux/module.h>

int initialization(void)
{
	printk(KERN_INFO "hello world\n");
	return 0;
}
void cleanup(void)
{
	printk(KERN_INFO "bye world\n");
	return ;
}

module_init(initialization);
module_exit(cleanup);

MODULE_LICENSE("GPL");
