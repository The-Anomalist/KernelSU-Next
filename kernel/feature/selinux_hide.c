#include <linux/cred.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "klog.h"
#include "policy/feature.h"
#include "selinux/policy_backup.h"
#include "selinux_hide.h"

static DEFINE_MUTEX(selinux_hide_mutex);

static bool ksu_selinux_hide_enabled __read_mostly;

struct selinux_state *ksu_selinux_hide_state_for_current(void)
{
    struct selinux_state *state;

    if (!READ_ONCE(ksu_selinux_hide_enabled))
        return NULL;

    /*
     * Match upstream behavior: hide KernelSU SELinux modifications
     * from Android application UIDs only.
     */
    if (current_uid().val < 10000)
        return NULL;

    state = ksu_get_backup_selinux_state();
    return state;
}

static int selinux_hide_feature_get(u64 *value)
{
    *value = READ_ONCE(ksu_selinux_hide_enabled) ? 1 : 0;
    return 0;
}

static int selinux_hide_feature_set(u64 value)
{
    bool enable = value != 0;

    mutex_lock(&selinux_hide_mutex);

    if (enable && !ksu_get_backup_selinux_state()) {
        pr_err("selinux_hide: pristine SELinux policy is unavailable\n");
        mutex_unlock(&selinux_hide_mutex);
        return -EAGAIN;
    }

    WRITE_ONCE(ksu_selinux_hide_enabled, enable);

    pr_info("selinux_hide: set to %d\n", enable);

    mutex_unlock(&selinux_hide_mutex);
    return 0;
}

static const struct ksu_feature_handler selinux_hide_handler = {
    .feature_id = KSU_FEATURE_SELINUX_HIDE,
    .name = "selinux_hide",
    .get_handler = selinux_hide_feature_get,
    .set_handler = selinux_hide_feature_set,
};

void __init ksu_selinux_hide_init(void)
{
    if (ksu_register_feature_handler(&selinux_hide_handler)) {
        pr_err("Failed to register selinux_hide feature handler\n");
        return;
    }

    pr_info("selinux_hide: feature registered\n");
}

void __exit ksu_selinux_hide_exit(void)
{
    WRITE_ONCE(ksu_selinux_hide_enabled, false);
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
    ksu_free_selinux_policy_backup();
}
