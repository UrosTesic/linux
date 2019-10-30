#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/linkage.h> 
#include <linux/unistd.h>

#ifdef CONFIG_TOCTTOU_PROTECTION
asmlinkage long __x64_sys_tocttou_test(__user long *arg)
{
    long check_copy;
    copy_from_user_check(&check_copy, arg, sizeof(long));

    if (!check_copy) {
        copy_from_user_unlock(arg, sizeof(long));
        return 0;
    }

    long working_copy;
    copy_from_user(&working_copy, arg, sizeof(long));
    if (!working_copy)
        return -1;
    else
        return 1;
}
#else
asmlinkage long __x64_sys_tocttou_test(__user long *arg)
{
    return 2;
}
#endif