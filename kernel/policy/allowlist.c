#include <linux/rcupdate.h>
#include <linux/limits.h>
#include <linux/rculist.h>
#include <linux/mutex.h>
#include <linux/task_work.h>
#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler_types.h>
#endif
#include <linux/hashtable.h>
#include <linux/kref.h>
#include <linux/namei.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/workqueue.h>

#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "compat/kernel_compat.h"
#include "runtime/ksud_boot.h"
#include "selinux/selinux.h"
#include "policy/allowlist.h"
#include "feature/shell_su_adb_only.h"
#include "manager/manager_identity.h"
#include "infra/su_mount_ns.h"

#define FILE_MAGIC 0x7f4b5355 // ' KSU', u32
#define FILE_FORMAT_VERSION 4 // u32

#define KSU_APP_PROFILE_PRESERVE_UID 9999 // NOBODY_UID
#define KSU_DEFAULT_SELINUX_DOMAIN "u:r:" KERNEL_SU_DOMAIN ":s0"

static DEFINE_MUTEX(allowlist_mutex);

// default profiles, these may be used frequently, so we cache it
static struct root_profile default_root_profile;
static struct non_root_profile default_non_root_profile;

static void __init init_default_profiles()
{
	kernel_cap_t full_cap = CAP_FULL_SET;

    default_root_profile.uid = 0;
    default_root_profile.gid = 0;
    default_root_profile.groups_count = 1;
    default_root_profile.groups[0] = 0;
    memcpy(&default_root_profile.capabilities.effective, &full_cap,
           sizeof(default_root_profile.capabilities.effective));
    default_root_profile.namespaces = KSU_NS_INHERITED;
    strcpy(default_root_profile.selinux_domain, KSU_DEFAULT_SELINUX_DOMAIN);

	// This means that we will umount modules by default!
	default_non_root_profile.umount_modules = true;

	default_root_profile.flags = 0;
}

struct perm_data {
    struct hlist_node list;
    struct rcu_head rcu;
    struct kref ref;
    struct app_profile profile;
};

// protected by rcu
#define ALLOW_LIST_BITS 8
static DEFINE_HASHTABLE(allow_list, ALLOW_LIST_BITS);
static u16 allow_list_count = 0;

#define KERNEL_SU_ALLOWLIST "/data/adb/ksu/.allowlist"

void ksu_persistent_allow_list(void);

void ksu_show_allow_list(void)
{
    int i;
    struct perm_data *p = NULL;
    pr_info("ksu_show_allow_list\n");
    rcu_read_lock();
    hash_for_each_rcu (allow_list, i, p, list) {
        pr_info("uid :%d, allow: %d\n", p->profile.curr_uid, p->profile.allow_su);
    }
    rcu_read_unlock();
}

struct app_profile *ksu_get_app_profile(uid_t uid)
{
    struct perm_data *p = NULL;
    bool found;

retry:
    found = false;
    hash_for_each_possible_rcu (allow_list, p, list, uid) {
        if (uid == p->profile.curr_uid) {
            // found it, override it with ours
            found = true;
            break;
        }
    }

    if (!found)
        return NULL;

    if (!kref_get_unless_zero(&p->ref)) {
        goto retry;
    }

    return &p->profile;
}

static inline bool forbid_system_uid(uid_t uid)
{
#define SHELL_UID 2000
#define SYSTEM_UID 1000
	return uid < SHELL_UID && uid != SYSTEM_UID;
}

static bool profile_valid(struct app_profile *profile)
{
	if (!profile) {
		return false;
	}

	if (strnlen(profile->key, sizeof(profile->key)) >= sizeof(profile->key)) {
		pr_err("invalid app_profile key\n");
		return false;
	}

	if (profile->version != KSU_APP_PROFILE_VER) {
		pr_info("Unsupported profile version: %d\n", profile->version);
		return false;
	}

	if (profile->allow_su) {
#ifndef CONFIG_KSU_DISABLE_POLICY
		if (profile->rp_config.profile.groups_count > KSU_MAX_GROUPS) {
			pr_err("invalid groups_count in app_profile: %s\n", profile->key);
			return false;
		}

		static const size_t domain_len = sizeof(profile->rp_config.profile.selinux_domain);
		size_t len = strnlen(profile->rp_config.profile.selinux_domain, domain_len);

		if (len == 0 || len >= domain_len) {
			pr_err("invalid selinux_domain in app_profile: %s\n", profile->key);
			return false;
		}
#endif
	}

	return true;
}


static void release_perm_data(struct kref *ref)
{
    struct perm_data *p = container_of(ref, struct perm_data, ref);
    kfree_rcu(p, rcu);
}

static void put_perm_data(struct perm_data *data)
{
    kref_put(&data->ref, release_perm_data);
}

int ksu_set_app_profile(struct app_profile *profile)
{
    struct perm_data *p, *np;
    int result = 0;

    if (!profile_valid(profile)) {
        pr_err("Failed to set app profile: invalid profile!\n");
        return -EINVAL;
    }

#ifdef CONFIG_KSU_DISABLE_POLICY
    if (profile->allow_su) {
        profile->rp_config.use_default = true;
        memset(profile->rp_config.template_name, 0, sizeof(profile->rp_config.template_name));
        memset(&profile->rp_config.profile, 0, sizeof(profile->rp_config.profile));
    } else {
        profile->nrp_config.use_default = true;
        memset(&profile->nrp_config.profile, 0, sizeof(profile->nrp_config.profile));
    }
#endif


    // only allow default non root profile
    if (unlikely(profile->curr_uid == KSU_APP_PROFILE_PRESERVE_UID && strcmp(profile->key, "$") != 0)) {
        return -EINVAL;
    }

    mutex_lock(&allowlist_mutex);

    hash_for_each_possible (allow_list, p, list, profile->curr_uid) {
        if (profile->curr_uid == p->profile.curr_uid) {
            if (strcmp(profile->key, p->profile.key) != 0) {
                pr_warn("ksu_set_app_profile: key changed: uid=%d orig=%s new=%s\n", profile->curr_uid, p->profile.key,
                        profile->key);
            }
            // found it, just override it all!
            np = (struct perm_data *)kzalloc(sizeof(struct perm_data),
                                             GFP_KERNEL);
            if (!np) {
                result = -ENOMEM;
                goto out_unlock;
            }
            kref_init(&np->ref);
            memcpy(&np->profile, profile, sizeof(*profile));
            hlist_replace_rcu(&p->list, &np->list);
            put_perm_data(p);
            goto out;
        }
    }

    if (unlikely(allow_list_count == U16_MAX)) {
        pr_err("too many app profile\n");
        result = -E2BIG;
        goto out_unlock;
    }

    // not found, alloc a new node!
    np = (struct perm_data *)kzalloc(sizeof(struct perm_data), GFP_KERNEL);
    if (!np) {
        pr_err("ksu_set_app_profile alloc failed\n");
        result = -ENOMEM;
        goto out_unlock;
    }

    kref_init(&np->ref);
    memcpy(&np->profile, profile, sizeof(*profile));
    if (profile->allow_su) {
        pr_info("set root profile, key: %s, uid: %d, gid: %d, context: %s\n", profile->key, profile->curr_uid,
                profile->rp_config.profile.gid,
                profile->rp_config.profile.selinux_domain);
    } else {
        pr_info("set app profile, key: %s, uid: %d, umount modules: %d\n", profile->key, profile->curr_uid,
                profile->nrp_config.profile.umount_modules);
    }

    hash_add_rcu(allow_list, &np->list, np->profile.curr_uid);
    ++allow_list_count;

out:
    result = 0;

    if (unlikely(profile->curr_uid == KSU_APP_PROFILE_PRESERVE_UID)) {
        // set default non root profile
        default_non_root_profile.umount_modules = profile->nrp_config.profile.umount_modules;
    }

out_unlock:
    mutex_unlock(&allowlist_mutex);
    return result;
}

bool __ksu_is_allow_uid(uid_t uid)
{
	struct perm_data *p;

	if (forbid_system_uid(uid)) {
		// do not bother going through the list if it's system
		return false;
	}

	if (unlikely(is_uid_manager(uid))) {
		// manager is always allowed!
		return true;
	}

	if (unlikely(allow_shell) && uid == SHELL_UID) {
		return true;
	}

	rcu_read_lock();
	hash_for_each_possible_rcu (allow_list, p, list, uid) {
		if (uid == p->profile.curr_uid && p->profile.allow_su) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	return false;
}

bool ksu_is_uid_granted_root(uid_t uid)
{
	if (unlikely(uid == 0)) {
		// already root, but only allow our domain.
		return is_ksu_domain();
	}
	return __ksu_is_allow_uid(uid);
}

bool __ksu_is_allow_uid_for_current(uid_t uid)
{
	if (unlikely(uid == SHELL_UID) && !ksu_shell_su_allowed_for_current()) {
		return false;
	}
	return ksu_is_uid_granted_root(uid);
}

bool ksu_uid_should_umount(uid_t uid)
{
    struct app_profile *profile;
    bool res;
    if (likely(ksu_is_manager_appid_valid()) && unlikely(ksu_get_manager_appid() == uid % PER_USER_RANGE)) {
        // we should not umount on manager!
        return false;
    }
#ifdef CONFIG_KSU_DISABLE_POLICY
    return !__ksu_is_allow_uid(uid);
#else
    rcu_read_lock();
    profile = ksu_get_app_profile(uid);
    if (!profile) {
        // no app profile found, it must be non root app
        res = default_non_root_profile.umount_modules;
    } else if (profile->allow_su) {
        // if found and it is granted to su, we shouldn't umount for it
        res = false;
    } else {
        // found an app profile
        if (profile->nrp_config.use_default) {
            res = default_non_root_profile.umount_modules;
        } else {
            res = profile->nrp_config.profile.umount_modules;
        }
    }
    rcu_read_unlock();

    if (profile)
        ksu_put_app_profile(profile);
    return res;
#endif
}

void ksu_put_app_profile(struct app_profile *profile)
{
    struct perm_data *p = container_of(profile, struct perm_data, profile);
    put_perm_data(p);
}

struct root_profile *ksu_get_root_profile(uid_t uid)
{
#ifdef CONFIG_KSU_DISABLE_POLICY
    (void)uid;
    return &default_root_profile;
#else
    struct perm_data *p = NULL;
    struct root_profile *res;

    rcu_read_lock();
    if (is_uid_manager(uid)) {
        goto use_default;
    }

    if (unlikely(allow_shell && uid == SHELL_UID)) {
        goto use_default;
    }

retry:
    res = NULL;
    hash_for_each_possible_rcu (allow_list, p, list, uid) {
        if (uid == p->profile.curr_uid && p->profile.allow_su) {
            if (!p->profile.rp_config.use_default) {
                if (!kref_get_unless_zero(&p->ref)) {
                    goto retry;
                }
                res = &p->profile.rp_config.profile;
            }
            break;
        }
    }

    if (unlikely(!res)) {
    use_default:
        res = &default_root_profile;
    }

    rcu_read_unlock();
    return res;
#endif
}

void ksu_put_root_profile(struct root_profile *profile)
{
    if (likely(profile == &default_root_profile))
        return;
    struct perm_data *p = container_of(profile, struct perm_data, profile.rp_config.profile);
    put_perm_data(p);
}

bool ksu_get_allow_list(int *array, u16 length, u16 *out_length, u16 *out_total,
                        bool allow)
{
    struct perm_data *p = NULL;
    u16 i = 0, j = 0;
    int iter;
    rcu_read_lock();
    hash_for_each_rcu (allow_list, iter, p, list) {
        // pr_info("get_allow_list uid: %d allow: %d\n", p->uid, p->allow);
        if (p->profile.allow_su == allow && !is_uid_manager(p->profile.curr_uid)) {
            if (j < length) {
                array[j++] = p->profile.curr_uid;
            }
            ++i;
        }
    }
    rcu_read_unlock();
    if (out_length) {
        *out_length = j;
    }
    if (out_total) {
        *out_total = i;
    }

	return true;
}

/* All callers coalesce onto this worker; PID 1 never performs the file I/O. */
#define KSU_ALLOWLIST_DIR "/data/adb/ksu"
#define KSU_ALLOWLIST_NAME ".allowlist"
#define KSU_ALLOWLIST_TMP_NAME ".allowlist.tmp"

static int allowlist_unlink_tmp(struct path *parent, struct file *expected)
{
	struct dentry *dentry;
	struct inode *dir = d_inode(parent->dentry);
	int ret;

	inode_lock(dir);
	dentry = lookup_one_len(KSU_ALLOWLIST_TMP_NAME, parent->dentry,
				sizeof(KSU_ALLOWLIST_TMP_NAME) - 1);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto out_unlock;
	}
	if (d_is_negative(dentry)) {
		ret = 0;
	} else if (expected && dentry != expected->f_path.dentry) {
		ret = -ESTALE;
	} else {
		ret = vfs_unlink(dir, dentry, NULL);
	}
	dput(dentry);
out_unlock:
	inode_unlock(dir);
	return ret;
}

static int allowlist_commit_tmp(struct path *parent, struct file *expected)
{
	struct dentry *old, *new;
	struct inode *dir = d_inode(parent->dentry);
	int ret;

	/* Same-directory rename; hold the parent exclusively for both lookups. */
	lock_rename(parent->dentry, parent->dentry);
	old = lookup_one_len(KSU_ALLOWLIST_TMP_NAME, parent->dentry,
			     sizeof(KSU_ALLOWLIST_TMP_NAME) - 1);
	if (IS_ERR(old)) {
		ret = PTR_ERR(old);
		goto out_unlock;
	}
	if (d_is_negative(old) || old != expected->f_path.dentry) {
		ret = -ESTALE;
		goto out_old;
	}
	new = lookup_one_len(KSU_ALLOWLIST_NAME, parent->dentry,
			     sizeof(KSU_ALLOWLIST_NAME) - 1);
	if (IS_ERR(new)) {
		ret = PTR_ERR(new);
		goto out_old;
	}
	ret = vfs_rename(dir, old, dir, new, NULL, 0);
	dput(new);
out_old:
	dput(old);
out_unlock:
	unlock_rename(parent->dentry, parent->dentry);
	return ret;
}

static int allowlist_write_all(struct file *file, const void *data,
			       size_t size, loff_t *pos)
{
	const char *cursor = data;
	ssize_t written;

	while (size) {
		written = ksu_kernel_write_compat(file, cursor, size, pos);
		if (written <= 0)
			return written ? (int)written : -EIO;
		cursor += written;
		size -= written;
	}
	return 0;
}

static void do_persistent_allow_list(struct work_struct *work)
{
	const u32 magic = FILE_MAGIC;
	const u32 version = FILE_FORMAT_VERSION;
	struct app_profile *profiles;
	struct perm_data *p;
	struct path parent;
	struct file *fp, *directory;
	const struct cred *saved;
	loff_t off = 0;
	size_t count = 0;
	int i, ret;

	/* Snapshot under the list mutex; do not hold it during storage I/O. */
	mutex_lock(&allowlist_mutex);
	profiles = kvmalloc_array(max_t(size_t, allow_list_count, 1),
				 sizeof(*profiles), GFP_KERNEL);
	if (profiles) {
		hash_for_each(allow_list, i, p, list)
			memcpy(&profiles[count++], &p->profile, sizeof(*profiles));
	}
	mutex_unlock(&allowlist_mutex);
	if (!profiles) {
		pr_err("save_allow_list: snapshot allocation failed\n");
		return;
	}

	saved = override_creds(ksu_cred);
	ret = kern_path(KSU_ALLOWLIST_DIR, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&parent);
	if (ret)
		goto out_creds;
	ret = mnt_want_write(parent.mnt);
	if (ret)
		goto out_path;

	/* A leftover staging file can remain after an interrupted prior boot. */
	ret = allowlist_unlink_tmp(&parent, NULL);
	if (ret)
		goto out_write;
	fp = file_open_root(parent.dentry, parent.mnt, KSU_ALLOWLIST_TMP_NAME,
			    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
	if (IS_ERR(fp)) {
		ret = PTR_ERR(fp);
		goto out_write;
	}
	ret = allowlist_write_all(fp, &magic, sizeof(magic), &off);
	if (!ret)
		ret = allowlist_write_all(fp, &version, sizeof(version), &off);
	if (!ret)
		ret = allowlist_write_all(fp, profiles,
					 count * sizeof(*profiles), &off);
	if (!ret)
		ret = vfs_fsync(fp, 0);
	if (!ret)
		ret = allowlist_commit_tmp(&parent, fp);
	if (ret)
		allowlist_unlink_tmp(&parent, fp);
	filp_close(fp, NULL);
	if (!ret) {
		/* Persist the replacement directory entry as well as its contents. */
		directory = dentry_open(&parent, O_RDONLY | O_DIRECTORY,
				       current_cred());
		if (IS_ERR(directory)) {
			ret = PTR_ERR(directory);
		} else {
			ret = vfs_fsync(directory, 0);
			filp_close(directory, NULL);
		}
	}
out_write:
	mnt_drop_write(parent.mnt);
out_path:
	path_put(&parent);
out_creds:
	revert_creds(saved);
	kvfree(profiles);
	if (ret)
		pr_err("save_allow_list: persistence failed: %d\n", ret);
}

static DECLARE_WORK(allowlist_save_work, do_persistent_allow_list);

void ksu_persistent_allow_list(void)
{
	schedule_work(&allowlist_save_work);
}

static void migrate_profile(u32 version, struct app_profile *profile)
{
    char *domain;
    static const size_t domain_len = sizeof(profile->rp_config.profile.selinux_domain);

    switch (version) {
    case 2:
        if (profile->allow_su) {
            domain = profile->rp_config.profile.selinux_domain;
            if (strncmp(domain, "u:r:su:s0", domain_len) == 0) {
                __strscpy_pad(domain, KSU_DEFAULT_SELINUX_DOMAIN, domain_len);
                pr_info("migrated domain of profile: %s\n", profile->key);
            }
        }
        /* fall through */
    case 3:
        if (profile->allow_su) {
            profile->rp_config.profile.flags = FLAG_KSU_NO_NEW_PRIVS;
        }
        break;
    }

    profile->version = KSU_APP_PROFILE_VER;
}

void ksu_load_allow_list()
{
#ifdef CONFIG_KSU_DISABLE_POLICY
	pr_info("allowlist load skipped because policy is disabled\n");
	return;
#endif

	loff_t off = 0;
	ssize_t ret = 0;
	struct file *fp = NULL;
	u32 magic;
	u32 version;
	size_t app_profile_size;

	// load allowlist now!
	fp = filp_open(KERNEL_SU_ALLOWLIST, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err("load_allow_list open file failed: %ld\n", PTR_ERR(fp));
		return;
	}

	// verify magic
	if (kernel_read(fp, &magic, sizeof(magic), &off) != sizeof(magic) ||
	    magic != FILE_MAGIC) {
		pr_err("allowlist file invalid: %d!\n", magic);
		goto exit;
	}

	// get file version
	if (kernel_read(fp, &version, sizeof(version), &off) != sizeof(version)) {
		pr_err("allowlist read version: %d failed\n", version);
		goto exit;
	}

	if (version < 2 || version > KSU_APP_PROFILE_VER) {
		pr_err("invalid allowlist version: %d\n", version);
		goto exit;
	}

	pr_info("allowlist version: %d\n", version);

	static const size_t kAppProfileSizePreV4 = 776;
	app_profile_size = version < KSU_APP_PROFILE_VER ? kAppProfileSizePreV4 : sizeof(struct app_profile);

	while (true) {
		struct app_profile profile;

		ret = kernel_read(fp, &profile, app_profile_size, &off);

		if (ret != app_profile_size) {
			if (ret != 0)
				pr_info("load_allow_list read err: %zd\n", ret);
			break;
		}

		migrate_profile(version, &profile);

		pr_info("load_allow_uid, name: %s, uid: %d, allow: %d\n", profile.key, profile.curr_uid, profile.allow_su);
		ksu_set_app_profile(&profile);
	}
	ksu_show_allow_list();
	filp_close(fp, 0);
	if (version < KSU_APP_PROFILE_VER)
		ksu_persistent_allow_list();
	return;

exit:
	ksu_show_allow_list();
	filp_close(fp, 0);
}

void ksu_prune_allowlist(bool (*is_uid_valid)(uid_t, char *, void *),
				void *data)
{
    struct perm_data *np = NULL;
    struct hlist_node *tmp;
    int i;

    if (!ksu_boot_completed) {
        pr_info("boot not completed, skip prune\n");
        return;
    }

    bool modified = false;
    mutex_lock(&allowlist_mutex);
    hash_for_each_safe (allow_list, i, tmp, np, list) {
        uid_t uid = np->profile.curr_uid;
        char *package = np->profile.key;
        // we use this uid for special cases, don't prune it!
        bool is_preserved_uid = uid == KSU_APP_PROFILE_PRESERVE_UID || uid == WEBVIEW_ZYGOTE_UID;
        if (!is_preserved_uid && !is_uid_valid(uid, package, data)) {
            modified = true;
            pr_info("prune uid: %d, package: %s\n", uid, package);
            hlist_del_rcu(&np->list);
            put_perm_data(np);
            --allow_list_count;
        }
    }
    mutex_unlock(&allowlist_mutex);

    if (modified) {
        smp_mb();
        ksu_persistent_allow_list();
    }
}

void __init ksu_allowlist_init(void)
{
	init_default_profiles();
}

void __exit ksu_allowlist_exit(void)
{
	struct perm_data *np = NULL;
	struct hlist_node *tmp;
	int i;

	cancel_work_sync(&allowlist_save_work);

	// free allowlist
	mutex_lock(&allowlist_mutex);
	hash_for_each_safe (allow_list, i, tmp, np, list) {
		hlist_del(&np->list);
		put_perm_data(np);
	}
	mutex_unlock(&allowlist_mutex);
}