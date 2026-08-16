#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>

#define SUSFS_MAGIC 0xFAFAFAFA
#define SUSFS_REPORT_BUFSIZE 16
#define SUSFS_ENABLED_FEATURES_SIZE 8192

struct ksu_susfs_version {
	char version[SUSFS_REPORT_BUFSIZE];
	int err;
};

struct ksu_susfs_variant {
	char variant[SUSFS_REPORT_BUFSIZE];
	int err;
};

struct ksu_susfs_enabled_features {
	char features[SUSFS_ENABLED_FEATURES_SIZE];
	int err;
};

/*
 * sys_reboot operational ABI used by the installed universal ksu_susfs
 * helper. Keep this definition wire-compatible with userspace: bool
 * enabled followed by the naturally aligned int err.
 */
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
struct ksu_susfs_log_v2000 {
	bool enabled;
	int err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
struct ksu_susfs_sus_path_v2000_new {
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
struct ksu_susfs_sus_kstat_v2000 {
	bool is_statically;
	unsigned long target_ino;
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	unsigned int spoofed_nlink;
	long long spoofed_size;
	long spoofed_atime_tv_sec;
	long spoofed_mtime_tv_sec;
	long spoofed_ctime_tv_sec;
	long spoofed_atime_tv_nsec;
	long spoofed_mtime_tv_nsec;
	long spoofed_ctime_tv_nsec;
	unsigned long spoofed_blksize;
	unsigned long long spoofed_blocks;
	int err;
};

static void ksu_susfs_kstat_to_legacy(struct st_susfs_sus_kstat *out,
	const struct ksu_susfs_sus_kstat_v2000 *in)
{
	memset(out, 0, sizeof(*out));
	out->is_statically = in->is_statically ? 1 : 0;
	out->target_ino = in->target_ino;
	strscpy(out->target_pathname, in->target_pathname, sizeof(out->target_pathname));
	out->spoofed_ino = in->spoofed_ino;
	out->spoofed_dev = in->spoofed_dev;
	out->spoofed_nlink = in->spoofed_nlink;
	out->spoofed_size = in->spoofed_size;
	out->spoofed_atime_tv_sec = in->spoofed_atime_tv_sec;
	out->spoofed_mtime_tv_sec = in->spoofed_mtime_tv_sec;
	out->spoofed_ctime_tv_sec = in->spoofed_ctime_tv_sec;
	out->spoofed_atime_tv_nsec = in->spoofed_atime_tv_nsec;
	out->spoofed_mtime_tv_nsec = in->spoofed_mtime_tv_nsec;
	out->spoofed_ctime_tv_nsec = in->spoofed_ctime_tv_nsec;
	out->spoofed_blksize = in->spoofed_blksize;
	out->spoofed_blocks = in->spoofed_blocks;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
struct ksu_susfs_sus_mount_v2000 {
	struct st_susfs_sus_mount info;
	int err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
struct ksu_susfs_try_umount_v2000 {
	struct st_susfs_try_umount info;
	int err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
struct ksu_susfs_uname_v2000 {
	struct st_susfs_uname info;
	int err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
struct ksu_susfs_open_redirect_v2000 {
	struct st_susfs_open_redirect info;
	int err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#define KSU_SUSFS_REBOOT_CMDLINE_SIZE 8192
struct ksu_susfs_cmdline_v2000 {
	char fake_cmdline_or_bootconfig[KSU_SUSFS_REBOOT_CMDLINE_SIZE];
	int err;
};
#endif

static int ksu_susfs_return_err(void __user *arg, size_t offset, int err)
{
	if (copy_to_user((char __user *)arg + offset, &err, sizeof(err)))
		return -EFAULT;

	return 0;
}

static int ksu_susfs_show_version(void __user *arg)
{
	struct ksu_susfs_version out = { .err = 0 };

	strlcpy(out.version, SUSFS_VERSION, sizeof(out.version));
	return copy_to_user(arg, &out, sizeof(out)) ? -EFAULT : 0;
}

static int ksu_susfs_show_variant(void __user *arg)
{
	struct ksu_susfs_variant out = { .err = 0 };

	strlcpy(out.variant, SUSFS_VARIANT, sizeof(out.variant));
	return copy_to_user(arg, &out, sizeof(out)) ? -EFAULT : 0;
}

static int ksu_susfs_show_enabled_features(void __user *arg)
{
	struct ksu_susfs_enabled_features *out;
	size_t len = 0;
	int ret;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

#define KSU_SUSFS_ADD_FEATURE(_name) \
	do { \
		if (len < sizeof(out->features)) \
			len += scnprintf(out->features + len, \
					 sizeof(out->features) - len, "%s\n", (_name)); \
	} while (0)

	KSU_SUSFS_ADD_FEATURE("SUSFS");
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
	KSU_SUSFS_ADD_FEATURE("MAGIC_MOUNT");
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	KSU_SUSFS_ADD_FEATURE("SUS_PATH");
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	KSU_SUSFS_ADD_FEATURE("SUS_MOUNT");
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT_MNT_ID_REORDER
	KSU_SUSFS_ADD_FEATURE("SUS_MOUNT_MNT_ID_REORDER");
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	KSU_SUSFS_ADD_FEATURE("AUTO_ADD_SUS_KSU_DEFAULT_MOUNT");
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	KSU_SUSFS_ADD_FEATURE("AUTO_ADD_SUS_BIND_MOUNT");
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	KSU_SUSFS_ADD_FEATURE("SUS_KSTAT");
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
	KSU_SUSFS_ADD_FEATURE("SUS_OVERLAYFS");
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	KSU_SUSFS_ADD_FEATURE("TRY_UMOUNT");
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	KSU_SUSFS_ADD_FEATURE("AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT");
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	KSU_SUSFS_ADD_FEATURE("SPOOF_UNAME");
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	KSU_SUSFS_ADD_FEATURE("ENABLE_LOG");
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
	KSU_SUSFS_ADD_FEATURE("HIDE_KSU_SUSFS_SYMBOLS");
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	KSU_SUSFS_ADD_FEATURE("SPOOF_CMDLINE_OR_BOOTCONFIG");
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	KSU_SUSFS_ADD_FEATURE("OPEN_REDIRECT");
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	KSU_SUSFS_ADD_FEATURE("SUS_SU");
#endif

#undef KSU_SUSFS_ADD_FEATURE

	out->err = 0;
	ret = copy_to_user(arg, out, sizeof(*out)) ? -EFAULT : 0;
	kfree(out);
	return ret;
}
#endif

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"

#include "tiny_sulog.h"

uint32_t ksuver_override = 0;

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	pr_info("ksu fd released\n");
	return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	// Create anonymous inode file
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);

	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

	return fd;
}

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

#if defined(CONFIG_KSU_SUSFS) && defined(CONFIG_KSU_MANUAL_HOOK)
	if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {
		int susfs_ret;

		switch (cmd) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		case CMD_SUSFS_ADD_SUS_PATH: {
			struct ksu_susfs_sus_path_v2000_new path;
			void __user *uarg = (void __user *)*arg;
			if (copy_from_user(&path, uarg, sizeof(path))) {
				susfs_ret = -EFAULT;
				break;
			}
			path.target_pathname[SUSFS_MAX_LEN_PATHNAME - 1] = '\0';
			path.err = susfs_add_sus_path_from_kernel(path.target_pathname);
			if (copy_to_user(uarg, &path, sizeof(path)))
				susfs_ret = -EFAULT;
			else
				susfs_ret = 0;
			break;
		}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		case CMD_SUSFS_ADD_SUS_KSTAT:
		case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		case CMD_SUSFS_UPDATE_SUS_KSTAT: {
			struct ksu_susfs_sus_kstat_v2000 wire;
			struct st_susfs_sus_kstat legacy;
			void __user *uarg = (void __user *)*arg;
			int err;
			if (copy_from_user(&wire, uarg, sizeof(wire))) {
				susfs_ret = -EFAULT;
				break;
			}
			wire.target_pathname[SUSFS_MAX_LEN_PATHNAME - 1] = '\0';
			ksu_susfs_kstat_to_legacy(&legacy, &wire);
			if (cmd == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY)
				legacy.is_statically = 1;
			if (cmd == CMD_SUSFS_UPDATE_SUS_KSTAT)
				err = susfs_update_sus_kstat_from_kernel(&legacy);
			else
				err = susfs_add_sus_kstat_from_kernel(&legacy);
			wire.err = err;
			if (copy_to_user(uarg, &wire, sizeof(wire)))
				susfs_ret = -EFAULT;
			else
				susfs_ret = 0;
			break;
		}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		case CMD_SUSFS_ADD_SUS_MOUNT: {
			void __user *uarg = (void __user *)*arg;
			int err;

			err = susfs_add_sus_mount(
				(struct st_susfs_sus_mount __user *)uarg);
			susfs_ret = ksu_susfs_return_err(
				uarg,
				offsetof(struct ksu_susfs_sus_mount_v2000, err),
				err);
			break;
		}
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		case CMD_SUSFS_ADD_TRY_UMOUNT: {
			void __user *uarg = (void __user *)*arg;
			int err;

			err = susfs_add_try_umount(
				(struct st_susfs_try_umount __user *)uarg);
			susfs_ret = ksu_susfs_return_err(
				uarg,
				offsetof(struct ksu_susfs_try_umount_v2000, err),
				err);
			break;
		}
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		case CMD_SUSFS_SET_UNAME: {
			void __user *uarg = (void __user *)*arg;
			int err;

			err = susfs_set_uname(
				(struct st_susfs_uname __user *)uarg);
			susfs_ret = ksu_susfs_return_err(
				uarg,
				offsetof(struct ksu_susfs_uname_v2000, err),
				err);
			break;
		}
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: {
			void __user *uarg = (void __user *)*arg;
			int err;

			/*
			 * v1.5.5 consumes only its legacy 4096-byte payload.
			 * The reboot ABI reserves 8192 bytes before the trailing err.
			 */
			err = susfs_set_cmdline_or_bootconfig((char __user *)uarg);
			susfs_ret = ksu_susfs_return_err(
				uarg, offsetof(struct ksu_susfs_cmdline_v2000, err),
				err);
			break;
		}
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		case CMD_SUSFS_ADD_OPEN_REDIRECT: {
			void __user *uarg = (void __user *)*arg;
			int err;

			err = susfs_add_open_redirect(
				(struct st_susfs_open_redirect __user *)uarg);
			susfs_ret = ksu_susfs_return_err(
				uarg,
				offsetof(struct ksu_susfs_open_redirect_v2000, err),
				err);
			break;
		}
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		case CMD_SUSFS_ENABLE_LOG: {
			struct ksu_susfs_log_v2000 log;
			void __user *uarg = (void __user *)*arg;

			if (copy_from_user(&log, uarg, sizeof(log))) {
				susfs_ret = -EFAULT;
				break;
			}

			susfs_set_log(log.enabled);
			log.err = 0;

			if (copy_to_user(uarg, &log, sizeof(log)))
				susfs_ret = -EFAULT;
			else
				susfs_ret = 0;
			break;
		}
#endif
		case CMD_SUSFS_SHOW_VERSION:
			susfs_ret = ksu_susfs_show_version((void __user *)*arg);
			break;
		case CMD_SUSFS_SHOW_ENABLED_FEATURES:
			susfs_ret =
				ksu_susfs_show_enabled_features((void __user *)*arg);
			break;
		case CMD_SUSFS_SHOW_VARIANT:
			susfs_ret = ksu_susfs_show_variant((void __user *)*arg);
			break;
		default:
			return -EINVAL;
		}

		if (susfs_ret)
			pr_err("susfs cmd 0x%x failed: %d\n",
			       cmd, susfs_ret);
		return 0;
	}
#endif

#ifdef CONFIG_KSU_DEBUG
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1,
		magic2);
#endif

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		int fd = ksu_install_fd();
		// downstream: dereference all arg usage!
		if (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
			pr_err("install ksu fd reply err\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
		close_fd(fd);
#else
		__close_fd(current->files, fd);
#endif
		}
		return 0;
	}

	// extensions 
	u64 reply = (u64)*arg;

	if (magic2 == CHANGE_MANAGER_UID) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}
	
	if (magic2 == GET_SULOG_DUMP_V2) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		int ret = send_sulog_dump(*arg);
		if (ret)
			return 0;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {
		// only root is allowed for this command 
		if (current_uid().val != 0)
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// basically void * void __user * void __user *arg
		void ***ppptr = (uintptr_t)arg;

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		pr_info("sys_reboot: ppptr: 0x%lx \n", ppptr);

		// arg here is ***, dereference to pull out **
		if (copy_from_user(&u_pptr, (void __user *)*ppptr, sizeof(u_pptr)))
			return 0;

		pr_info("sys_reboot: u_pptr: 0x%lx \n", u_pptr);

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		pr_info("sys_reboot: u_ptr: 0x%lx \n", u_ptr);

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
			strscpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strscpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#else
			strlcpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strlcpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#endif
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		strscpy(u->release, release_buf, sizeof(u->release));
		strscpy(u->version, version_buf, sizeof(u->version));
#else
		strlcpy(u->release, release_buf, sizeof(u->release));
		strlcpy(u->version, version_buf, sizeof(u->version));
#endif
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
			return 0;
	}

	return 0;
}

#ifdef KSU_KPROBES_HOOK
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;

	return ksu_handle_sys_reboot(magic1, magic2, cmd, (void __user **)&arg4);
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};
#endif

void __init ksu_supercalls_init(void)
{
	int i;

	ksu_supercall_dump_commands();

#ifdef KSU_KPROBES_HOOK
	int rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
	} else {
		pr_info("reboot kprobe registered successfully\n");
	}
#endif

	sulog_init_heap(); // grab heap memory
}

void __exit ksu_supercalls_exit(void){
	struct mount_entry *entry, *tmp;

#ifdef KSU_KPROBES_HOOK
	unregister_kprobe(&reboot_kp);
#endif

	ksu_supercall_cleanup_state();
}
