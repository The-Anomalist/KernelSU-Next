#ifndef __KSU_SELINUX_POLICY_BACKUP_H
#define __KSU_SELINUX_POLICY_BACKUP_H

struct selinux_state;

int ksu_backup_selinux_policy(void);
void ksu_free_selinux_policy_backup(void);
struct selinux_state *ksu_get_backup_selinux_state(void);

#endif
