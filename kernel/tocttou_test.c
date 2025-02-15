#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

#define FILTERED_ARGUMENT 0
#define LEGAL_ARGUMENT 1
#define ILLEGAL_ARGUMENT -1

#ifdef CONFIG_TOCTTOU_PROTECTION
// Dummy systemcalls that sleep long enough to check for TOCTTOU
SYSCALL_DEFINE1(tocttou_test, long __user *, arg)
{
    long check_copy;
    long working_copy;

    copy_from_user(&check_copy, arg, sizeof(long));

    if (!check_copy) {
        return FILTERED_ARGUMENT;
    }

    ssleep(10);

    copy_from_user(&working_copy, arg, sizeof(long));
    if (!working_copy)
        return ILLEGAL_ARGUMENT;
    else
        return LEGAL_ARGUMENT;
}

SYSCALL_DEFINE1(tocttou_lock, long __user *, arg)
{
    return 0;
}

SYSCALL_DEFINE1(tocttou_unlock, long __user *, arg)
{
    return 0;
}
#else
SYSCALL_DEFINE1(tocttou_test, long __user *, arg)
{
    return 2;
}

SYSCALL_DEFINE1(tocttou_lock, long __user *, arg)
{
    return 2;
}

SYSCALL_DEFINE1(tocttou_unlock, long __user *, arg)
{
    return 2;
}
#endif