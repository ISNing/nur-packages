/*
 * memfd_ashmem_shim.c - AOSP Ashmem Shim for memfd (Safe OOT Implementation)
 * * Strategy:
 * 1. Use standard 'vm_map_ram' to patch fops (No CR0 hacking, No GPF crash).
 * 2. Gracefully degrade if memfd_fcntl is IBT-unsafe (No Missing ENDBR crash).
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
#include <linux/mman.h>
#include <linux/vmalloc.h> /* Required for vm_map_ram */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Isaac J. Manjarres <isaacmanjarres@google.com>");
MODULE_DESCRIPTION("Ashmem compatibility for memfd");

// ==========================================================================
// Part 1: Ashmem Protocol Definitions
// ==========================================================================

#define __ASHMEMIOC 0x77
#define ASHMEM_NAME_LEN 256

#define ASHMEM_SET_NAME        _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME        _IOW(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE        _IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE        _IO(__ASHMEMIOC, 4)
#define ASHMEM_SET_PROT_MASK   _IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK   _IO(__ASHMEMIOC, 6)
#define ASHMEM_PIN             _IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN           _IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS  _IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES _IO(__ASHMEMIOC, 10)
#define ASHMEM_GET_FILE_ID     _IO(__ASHMEMIOC, 11)

#define ASHMEM_NOT_PURGED 0
#define ASHMEM_IS_PINNED  1

struct ashmem_pin {
    u32 offset;
    u32 len;
};

#define MEMFD_PREFIX "memfd:"
#define MEMFD_PREFIX_LEN (sizeof(MEMFD_PREFIX) - 1)

// ==========================================================================
// Part 2: Kernel Symbol Resolution (IBT Safe)
// ==========================================================================

static long (*memfd_fcntl_ptr)(struct file *file, unsigned int cmd, unsigned long arg) = NULL;

static unsigned long lookup_symbol_via_kprobe(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) return 0;
    
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static void resolve_deps(void) {
    unsigned long addr = lookup_symbol_via_kprobe("memfd_fcntl");
    
    if (addr) {
        // IBT Check: XanMod kernel requires ENDBR64 (0xf3 0f 1e fa) at function entry
#ifdef CONFIG_X86_64
        u32 *insn = (u32 *)addr;
        // 0xfa1e0ff3 is Little Endian for f3 0f 1e fa
        if (insn && *insn != 0xfa1e0ff3) {
            pr_warn("memfd_ashmem_shim: 'memfd_fcntl' missing ENDBR64. Seal ops disabled for safety.\n");
            memfd_fcntl_ptr = NULL;
        } else {
            memfd_fcntl_ptr = (void *)addr;
        }
#else
        memfd_fcntl_ptr = (void *)addr;
#endif
    } else {
        pr_warn("memfd_ashmem_shim: 'memfd_fcntl' not found.\n");
    }
}

// ==========================================================================
// Part 3: AOSP Implementation Logic
// ==========================================================================

static long shim_memfd_fcntl(struct file *file, unsigned int cmd, unsigned long arg) {
    if (memfd_fcntl_ptr) return memfd_fcntl_ptr(file, cmd, arg);
    return -ENOSYS; 
}

static const char *get_memfd_name(struct file *file)
{
    const char *file_name = file->f_path.dentry->d_name.name;
    if (file_name != strstr(file_name, MEMFD_PREFIX)) return NULL;
    return file_name;
}

static long get_name(struct file *file, void __user *name)
{
    const char *file_name = get_memfd_name(file);
    size_t len;

    if (!file_name) return -EINVAL;
    file_name = &file_name[MEMFD_PREFIX_LEN];
    len = strlen(file_name) + 1;
    if (len > ASHMEM_NAME_LEN) return -EINVAL;
    return copy_to_user(name, file_name, len) ? -EFAULT : 0;
}

static long get_prot_mask(struct file *file)
{
    long prot_mask = PROT_READ | PROT_EXEC;
    long seals = shim_memfd_fcntl(file, F_GET_SEALS, 0);

    if (seals < 0) return seals;
    if (!(seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)))
        prot_mask |= PROT_WRITE;
    return prot_mask;
}

static long set_prot_mask(struct file *file, unsigned long prot)
{
    long curr_prot = get_prot_mask(file);
    if (curr_prot < 0) return curr_prot;

    prot |= PROT_READ | PROT_EXEC;
    if ((curr_prot & prot) != prot) return -EINVAL;

    if (!(prot & PROT_WRITE))
        return shim_memfd_fcntl(file, F_ADD_SEALS, F_SEAL_FUTURE_WRITE);

    return 0;
}

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
        // Core requirement for Redroid
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
// Part 4: The Safe Patching Mechanism (vm_map_ram)
// ==========================================================================

static struct file_operations *shmem_fops_ptr = NULL;
static long (*orig_ioctl)(struct file *, unsigned int, unsigned long) = NULL;

static long hooked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = memfd_ashmem_shim_ioctl(file, cmd, arg);
    if (ret != -ENOTTY) return ret;
    if (orig_ioctl) return orig_ioctl(file, cmd, arg);
    return -ENOTTY;
}

// Use standard kernel API to map the page as writable, avoiding CR0 pinning issues
static void patch_pointer(void *target, void *new_val)
{
    struct page *page;
    void *vaddr;
    unsigned long offset_in_page;

    if (is_vmalloc_addr(target))
        page = vmalloc_to_page(target);
    else
        page = virt_to_page(target);

    if (!page) {
        pr_err("memfd_ashmem_shim: Cannot resolve page for %p\n", target);
        return;
    }

    // Create a temporary writable alias
    vaddr = vm_map_ram(&page, 1, -1);
    if (!vaddr) {
        pr_err("memfd_ashmem_shim: vm_map_ram failed\n");
        return;
    }

    offset_in_page = (unsigned long)target & ~PAGE_MASK;
    
    // Perform the write safely
    memcpy(vaddr + offset_in_page, &new_val, sizeof(void *));

    vm_unmap_ram(vaddr, 1);
}

static int __init memfd_ashmem_shim_init(void)
{
    struct file *dummy_file;

    pr_info("memfd_ashmem_shim: Initializing (Safe Mode)...\n");

    resolve_deps();

    // Find shmem_file_operations via a dummy file
    dummy_file = shmem_kernel_file_setup("memfd_ashmem_shim_probe", 4096, 0);
    if (IS_ERR(dummy_file)) return PTR_ERR(dummy_file);

    shmem_fops_ptr = (struct file_operations *)dummy_file->f_op;
    fput(dummy_file);

    if (!shmem_fops_ptr) return -EFAULT;

    // Save original
    orig_ioctl = shmem_fops_ptr->unlocked_ioctl;

    // Apply patch safely
    patch_pointer(&shmem_fops_ptr->unlocked_ioctl, hooked_ioctl);

    pr_info("memfd_ashmem_shim: Patched shmem_fops->unlocked_ioctl successfully.\n");
    return 0;
}

static void __exit memfd_ashmem_shim_exit(void)
{
    if (shmem_fops_ptr) {
        patch_pointer(&shmem_fops_ptr->unlocked_ioctl, orig_ioctl);
        pr_info("memfd_ashmem_shim: Unhooked.\n");
    }
}

module_init(memfd_ashmem_shim_init);
module_exit(memfd_ashmem_shim_exit);