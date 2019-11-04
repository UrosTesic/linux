#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#ifdef CONFIG_TOCTTOU_PROTECTION
__attribute__((optimize("O0"))) SYSCALL_DEFINE1(tocttou_test, long __user *, arg)
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

__attribute__((optimize("O0"))) SYSCALL_DEFINE1(tocttou_lock, long __user *, arg)
{
    long check_copy;
    return copy_from_user_check(&check_copy, arg, sizeof(long));
}

__attribute__((optimize("O0"))) SYSCALL_DEFINE1(tocttou_unlock, long __user *, arg)
{
    copy_from_user_unlock(arg, sizeof(long));
    return 0;
}
#else
__attribute__((optimize("O0"))) SYSCALL_DEFINE1(tocttou_test, long __user *, arg)
{
    return 2;
}

__attribute__((optimize("O0"))) SYSCALL_DEFINE1(tocttou_lock, long __user *, arg)
{
    return 2;
}

__attribute__((optimize("O0"))) SYSCALL_DEFINE1(tocttou_unlock, long __user *, arg)
{
    return 2;
}
#endif