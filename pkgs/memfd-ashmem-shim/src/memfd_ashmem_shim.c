/*
 * memfd_ashmem_shim.c - OOT Kernel Module implementation of AOSP memfd-ashmem-shim
 * Strictly based on: system/core/libcutils/memfd-ashmem-shim.c
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/shmem_fs.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/mman.h> /* 关键修复：解决 PROT_WRITE/PROT_READ 未定义问题 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Isaac J. Manjarres <isaacmanjarres@google.com> (Original)");
MODULE_DESCRIPTION("Ashmem compatibility for memfd (OOT Module)");

// ==========================================================================
// Part 1: Definitions from memfd-ashmem-shim.h (Missing in Kernel)
// ==========================================================================

#define __ASHMEMIOC 0x77
#define ASHMEM_NAME_LEN 256

#define ASHMEM_SET_NAME        _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME        _IOW(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN]) // [新增]
#define ASHMEM_SET_SIZE        _IOW(__ASHMEMIOC, 3, size_t)                // [新增]
#define ASHMEM_GET_SIZE        _IO(__ASHMEMIOC, 4)
#define ASHMEM_SET_PROT_MASK   _IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK   _IO(__ASHMEMIOC, 6)                         // [新增]
#define ASHMEM_PIN             _IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN           _IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS  _IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES _IO(__ASHMEMIOC, 10)
#define ASHMEM_GET_FILE_ID     _IO(__ASHMEMIOC, 11)

// Return values
#define ASHMEM_NOT_PURGED 0
#define ASHMEM_IS_PINNED  1

struct ashmem_pin {
    u32 offset;
    u32 len;
};

#define MEMFD_PREFIX "memfd:"
#define MEMFD_PREFIX_LEN (sizeof(MEMFD_PREFIX) - 1)

// Forward declaration to fix warning
long memfd_ashmem_shim_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

// ==========================================================================
// Part 2: Dynamic Symbol Lookup (Kprobe Trick)
// ==========================================================================

static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;
static long (*memfd_fcntl_ptr)(struct file *file, unsigned int cmd, unsigned long arg) = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};
#endif

static int resolve_symbols(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("memfd_ashmem_shim: Failed to register kprobe to find kallsyms_lookup_name\n");
        return ret;
    }
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
#else
    kallsyms_lookup_name_ptr = kallsyms_lookup_name;
#endif

    if (!kallsyms_lookup_name_ptr) return -EFAULT;

    memfd_fcntl_ptr = (void *)kallsyms_lookup_name_ptr("memfd_fcntl");
    if (!memfd_fcntl_ptr) {
        pr_warn("memfd_ashmem_shim: Could not find 'memfd_fcntl'. functionality might be limited.\n");
    }
    return 0;
}

// Wrapper to call the resolved memfd_fcntl
static long memfd_fcntl(struct file *file, unsigned int cmd, unsigned long arg) {
    if (memfd_fcntl_ptr) {
        return memfd_fcntl_ptr(file, cmd, arg);
    }
    return -ENOSYS; 
}

// ==========================================================================
// Part 3: AOSP Implementation (Strictly Ported)
// ==========================================================================

static const char *get_memfd_name(struct file *file)
{
    const char *file_name = file->f_path.dentry->d_name.name;

    if (file_name != strstr(file_name, MEMFD_PREFIX))
        return NULL;

    return file_name;
}

static long get_name(struct file *file, void __user *name)
{
    const char *file_name = get_memfd_name(file);
    size_t len;

    if (!file_name)
        return -EINVAL;

    file_name = &file_name[MEMFD_PREFIX_LEN];
    len = strlen(file_name) + 1;
    if (len > ASHMEM_NAME_LEN)
        return -EINVAL;

    return copy_to_user(name, file_name, len) ? -EFAULT : 0;
}

static long get_prot_mask(struct file *file)
{
    long prot_mask = PROT_READ | PROT_EXEC;
    long seals = memfd_fcntl(file, F_GET_SEALS, 0);

    if (seals < 0)
        return seals;

    if (!(seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)))
        prot_mask |= PROT_WRITE;

    return prot_mask;
}

static long set_prot_mask(struct file *file, unsigned long prot)
{
    long curr_prot = get_prot_mask(file);
    long ret = 0;

    if (curr_prot < 0)
        return curr_prot;

    prot |= PROT_READ | PROT_EXEC;

    if ((curr_prot & prot) != prot)
        return -EINVAL;

    if (!(prot & PROT_WRITE))
        ret = memfd_fcntl(file, F_ADD_SEALS, F_SEAL_FUTURE_WRITE);

    return ret;
}

/*
 * memfd_ashmem_shim_ioctl - ioctl handler for ashmem commands
 */
long memfd_ashmem_shim_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = -ENOTTY;
    unsigned long inode_nr;

    switch (cmd) {
    case ASHMEM_SET_NAME:
    case ASHMEM_SET_SIZE:
        ret = -EINVAL;
        break;
    case ASHMEM_GET_NAME:
        ret = get_name(file, (void __user *)arg);
        break;
    case ASHMEM_GET_SIZE:
        ret = i_size_read(file_inode(file));
        break;
    case ASHMEM_SET_PROT_MASK:
        ret = set_prot_mask(file, arg);
        break;
    case ASHMEM_GET_PROT_MASK:
        ret = get_prot_mask(file);
        break;
    case ASHMEM_PIN:
        ret = ASHMEM_NOT_PURGED;
        break;
    case ASHMEM_UNPIN:
        ret = 0;
        break;
    case ASHMEM_GET_PIN_STATUS:
        ret = ASHMEM_IS_PINNED;
        break;
    case ASHMEM_PURGE_ALL_CACHES:
        ret = capable(CAP_SYS_ADMIN) ? 0 : -EPERM;
        break;
    case ASHMEM_GET_FILE_ID:
        inode_nr = file_inode(file)->i_ino;
        if (copy_to_user((void __user *)arg, &inode_nr, sizeof(inode_nr)))
            ret = -EFAULT;
        else
            ret = 0;
        break;
    }

    return ret;
}

// ==========================================================================
// Part 4: Hooking Mechanism (Hijack shmem_file_operations)
// ==========================================================================

static struct file_operations *shmem_fops_ptr = NULL;
static long (*orig_ioctl)(struct file *, unsigned int, unsigned long) = NULL;

static long hooked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = memfd_ashmem_shim_ioctl(file, cmd, arg);

    if (ret != -ENOTTY)
        return ret;

    if (orig_ioctl)
        return orig_ioctl(file, cmd, arg);

    return -ENOTTY;
}

static inline void my_write_cr0(unsigned long cr0) {
    asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
}

static void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    my_write_cr0(cr0 | 0x00010000);
}

static void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    my_write_cr0(cr0 & ~0x00010000);
}

static int __init memfd_ashmem_shim_init(void)
{
    struct file *dummy_file;
    int ret;

    pr_info("memfd_ashmem_shim: Initializing AOSP shim...\n");

    ret = resolve_symbols();
    if (ret) return ret;

    dummy_file = shmem_kernel_file_setup("memfd_ashmem_shim_probe", 4096, 0);
    if (IS_ERR(dummy_file)) {
        pr_err("memfd_ashmem_shim: Failed to create dummy shmem file.\n");
        return PTR_ERR(dummy_file);
    }

    shmem_fops_ptr = (struct file_operations *)dummy_file->f_op;
    fput(dummy_file);

    if (!shmem_fops_ptr) {
        pr_err("memfd_ashmem_shim: f_op was NULL!\n");
        return -EFAULT;
    }

    orig_ioctl = shmem_fops_ptr->unlocked_ioctl;

    preempt_disable();
    disable_write_protection();
    shmem_fops_ptr->unlocked_ioctl = hooked_ioctl;
    enable_write_protection();
    preempt_enable();

    pr_info("memfd_ashmem_shim: Hooked shmem_file_operations->unlocked_ioctl at %p\n", shmem_fops_ptr->unlocked_ioctl);
    return 0;
}

static void __exit memfd_ashmem_shim_exit(void)
{
    if (shmem_fops_ptr) {
        preempt_disable();
        disable_write_protection();
        shmem_fops_ptr->unlocked_ioctl = orig_ioctl;
        enable_write_protection();
        preempt_enable();
        pr_info("memfd_ashmem_shim: Unhooked.\n");
    }
}

module_init(memfd_ashmem_shim_init);
module_exit(memfd_ashmem_shim_exit);