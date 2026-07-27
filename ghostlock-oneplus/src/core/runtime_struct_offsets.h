#ifndef RUNTIME_STRUCT_OFFSETS_H
#define RUNTIME_STRUCT_OFFSETS_H

#include "../devices/offsets.h"

extern const struct kernel_offsets *active_offsets;

#define _RSO(field, fallback) \
  (active_offsets && active_offsets->field ? active_offsets->field : (fallback))

#undef FAKE_TASK_PRIO_OFF
#undef FAKE_TASK_NORMAL_PRIO_OFF
#undef FAKE_TASK_TASK_GROUP_OFF
#undef FAKE_TASK_PI_LOCK_OFF
#undef FAKE_TASK_PI_WAITERS_OFF
#undef FAKE_TASK_PI_TOP_TASK_OFF
#undef FAKE_TASK_PI_BLOCKED_ON_OFF
#undef MM_OWNER_OFF
#undef TASK_PID_OFF
#undef TASK_TGID_OFF
#undef TASK_REAL_PARENT_OFF
#undef TASK_ATOMIC_FLAGS_OFF
#undef TASK_REAL_CRED_OFF
#undef TASK_CRED_OFF
#undef TASK_COMM_OFF
#undef TASK_TASKS_OFF
#undef TASK_SECCOMP_OFF

#define FAKE_TASK_PRIO_OFF           _RSO(task_prio, 0x94)
#define FAKE_TASK_NORMAL_PRIO_OFF    _RSO(task_normal_prio, 0x9C)
#define FAKE_TASK_TASK_GROUP_OFF     _RSO(task_sched_task_group, 0x420)
#define FAKE_TASK_PI_LOCK_OFF        _RSO(task_pi_lock, 0x9EC)
#define FAKE_TASK_PI_WAITERS_OFF     _RSO(task_pi_waiters, 0xA00)
#define FAKE_TASK_PI_TOP_TASK_OFF    _RSO(task_pi_top_task, 0xA10)
#define FAKE_TASK_PI_BLOCKED_ON_OFF  _RSO(task_pi_blocked_on, 0xA18)
#define MM_OWNER_OFF                 _RSO(mm_owner, 0x410)
#define TASK_PID_OFF                 _RSO(task_pid, 0x708)
#define TASK_TGID_OFF                _RSO(task_tgid, 0x70C)
#define TASK_REAL_PARENT_OFF         _RSO(task_real_parent, 0x718)
#define TASK_ATOMIC_FLAGS_OFF        _RSO(task_atomic_flags, 0x6C8)
#define TASK_REAL_CRED_OFF           _RSO(task_real_cred, 0x8F8)
#define TASK_CRED_OFF                _RSO(task_cred, 0x900)
#define TASK_COMM_OFF                _RSO(task_comm, 0x910)
#define TASK_TASKS_OFF               _RSO(task_tasks, 0x638)
#define TASK_SECCOMP_OFF             _RSO(task_seccomp, 0x9C8)

#endif
