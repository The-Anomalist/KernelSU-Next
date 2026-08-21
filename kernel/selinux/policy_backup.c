#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "security.h"
#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/sidtab.h"

#include "klog.h"
#include "policy_backup.h"

static struct selinux_state ksu_backup_state;
static struct selinux_ss *ksu_backup_ss;

struct selinux_state *ksu_get_backup_selinux_state(void)
{
    return ksu_backup_ss ? &ksu_backup_state : NULL;
}

void ksu_free_selinux_policy_backup(void)
{
    if (!ksu_backup_ss)
        return;

    if (ksu_backup_ss->status_page) {
        __free_page(ksu_backup_ss->status_page);
        ksu_backup_ss->status_page = NULL;
    }

    if (ksu_backup_ss->sidtab) {
        sidtab_destroy(ksu_backup_ss->sidtab);
        kfree(ksu_backup_ss->sidtab);
        ksu_backup_ss->sidtab = NULL;
    }

    ksu_backup_ss->map.mapping = NULL;
    ksu_backup_ss->map.size = 0;

    policydb_destroy(&ksu_backup_ss->policydb);

    kfree(ksu_backup_ss);
    ksu_backup_ss = NULL;

    memset(&ksu_backup_state, 0, sizeof(ksu_backup_state));
}

int ksu_backup_selinux_policy(void)
{
    struct policy_file fp;
    void *policy_data = NULL;
    size_t policy_len = 0;
    struct page *live_status_page;
    struct page *backup_status_page;
    int ret;

    if (ksu_backup_ss)
        return 0;

    if (!selinux_initialized(&selinux_state) || !selinux_state.ss)
        return -EINVAL;

    ret = security_read_policy(&selinux_state,
                               &policy_data,
                               &policy_len);
    if (ret) {
        pr_err("policy_backup: security_read_policy failed: %d\n", ret);
        return ret;
    }

    ksu_backup_ss = kzalloc(sizeof(*ksu_backup_ss), GFP_KERNEL);
    if (!ksu_backup_ss) {
        ret = -ENOMEM;
        goto out_free_blob;
    }

    rwlock_init(&ksu_backup_ss->policy_rwlock);
    mutex_init(&ksu_backup_ss->status_lock);

    fp.data = policy_data;
    fp.len = policy_len;

    ret = policydb_read(&ksu_backup_ss->policydb, &fp);
    if (ret) {
        pr_err("policy_backup: policydb_read failed: %d\n", ret);
        goto out_free_ss;
    }

    ksu_backup_ss->policydb.len = policy_len;

    ksu_backup_ss->sidtab =
        kzalloc(sizeof(*ksu_backup_ss->sidtab), GFP_KERNEL);
    if (!ksu_backup_ss->sidtab) {
        ret = -ENOMEM;
        goto out_destroy_policy;
    }

    ret = policydb_load_isids(&ksu_backup_ss->policydb,
                              ksu_backup_ss->sidtab);
    if (ret) {
        pr_err("policy_backup: policydb_load_isids failed: %d\n", ret);
        goto out_free_sidtab;
    }

    ksu_backup_ss->map = selinux_state.ss->map;
    ksu_backup_ss->latest_granting =
        selinux_state.ss->latest_granting;

    memcpy(&ksu_backup_state,
           &selinux_state,
           sizeof(ksu_backup_state));

    ksu_backup_state.ss = ksu_backup_ss;

    /*
     * Freeze the current SELinux status page alongside the pristine
     * policy.  A lazily-created private status page would start with
     * sequence=0 and lose the legitimate early-boot status history.
     */
    live_status_page = selinux_kernel_status_page(&selinux_state);
    if (live_status_page) {
        backup_status_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!backup_status_page) {
            ret = -ENOMEM;
            goto out_destroy_backup;
        }

        mutex_lock(&selinux_state.ss->status_lock);
        memcpy(page_address(backup_status_page),
               page_address(live_status_page),
               sizeof(struct selinux_kernel_status));
        mutex_unlock(&selinux_state.ss->status_lock);

        ksu_backup_ss->status_page = backup_status_page;
    } else {
        pr_warn("policy_backup: SELinux status page unavailable\n");
    }

    pr_info("policy_backup: pristine SELinux policy ready\n");

    vfree(policy_data);
    return 0;

out_destroy_backup:
    ksu_free_selinux_policy_backup();
    vfree(policy_data);
    return ret;

out_free_sidtab:
    kfree(ksu_backup_ss->sidtab);
    ksu_backup_ss->sidtab = NULL;

out_destroy_policy:
    policydb_destroy(&ksu_backup_ss->policydb);

out_free_ss:
    kfree(ksu_backup_ss);
    ksu_backup_ss = NULL;

out_free_blob:
    vfree(policy_data);
    return ret;
}
