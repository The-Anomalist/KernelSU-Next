#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

struct selinux_state;

void ksu_selinux_hide_init(void);
void ksu_selinux_hide_exit(void);

/*
 * Returns the pristine SELinux state only when SELinux Hide is enabled
 * and the current task is an Android application UID.
 */
struct selinux_state *ksu_selinux_hide_state_for_current(void);

#endif
