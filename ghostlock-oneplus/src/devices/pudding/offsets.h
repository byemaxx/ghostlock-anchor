/* Xiaomi 17 (pudding) — SM8850 (canoe) / Snapdragon 8 Elite Gen 5
 * kernel_phys_load: 0xc7800000 from verified SM8850 (op15/CPH2749, same SoC)
 * SP diff=-64, SHIFT=0 */

/* 6.12.23 entry cross-checked against kallsyms recovered from the exact
 * boot.img (OS3.0.315.0.WPCCNXM):
 *   nfulnl_logger=0x023F21B0 (slide does stext = leaked - this; must be exact),
 *   loggers=0x023F20F0, loggers[0][1]=0x023F20F8,
 *   security_hook_active_capable_0=0x02674C18,
 *   ashmem_fops=0x013A4F48 verified 8/8 vtable slots hold fops_* pointers. */
OFFSETS_ENTRY("6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k",  /* OS3.0.315.0.WPCCNXM */
  .kernel_phys_load=0xc7800000, STRUCT_OFFSETS_6_12,
  .off_init_task=0x023FCF00, .off_init_cred=0x02412A68, .off_init_uts_ns=0x02586C90,
  .off_empty_zero_page=0x02626000, .off_root_task_group=0x0262E580,
  .off_selinux_enforcing=0x0267A5B8, .off_kptr_restrict=0x023FB638,
  .off_selinux_blob_sizes=0x018434E8, .off_security_hook_heads=0,
  .off_kmalloc_caches=0x0183D4C0, .off_anon_pipe_buf_ops=0x0121EE08,
  .off_ashmem_misc_fops=0, .off_ashmem_fops=0x013A4F48,
  .off_ashmem_ioctl=0x00D8691C, .off_ashmem_compat_ioctl=0x00D86F04,
  .off_ashmem_mmap=0x00D86F80, .off_ashmem_open=0x00D86FDC,
  .off_ashmem_release=0x00D869DC, .off_ashmem_show_fdinfo=0x00D86EDC,
  .off_configfs_read_iter=0x0051288C, .off_configfs_bin_write_iter=0x00512E38,
  .off_copy_splice_read=0x0048ED94, .off_noop_llseek=0x0043C3D8,
  .off_cap_capable_active=0x02674C18,
  .off_slide_nfulnl_logger=0x023F21B0, .off_slide_loggers_0_1=0x023F20F8,
  .off_slide_boot_id=0x0269B968,
  .off_system_unbound_wq=0x0183D250, .off_call_usermodehelper_exec_work=0x000F6744,
),
OFFSETS_ENTRY("6.12.69-android16-6-gb1493ec68d4a-abogki514973465-4k",  /* August 2026 update */
  .kernel_phys_load=0xc7800000, STRUCT_OFFSETS_6_12,
  .off_init_task=0x0255D900, .off_init_cred=0x025736B0, .off_init_uts_ns=0x026FAE88,
  .off_empty_zero_page=0x027A0000, .off_root_task_group=0x027A8800,
  .off_selinux_enforcing=0x027F8BC8, .off_kptr_restrict=0x0255C058,
  .off_selinux_blob_sizes=0x01922868, .off_security_hook_heads=0,
  .off_kmalloc_caches=0x019184C0, .off_anon_pipe_buf_ops=0x012B09C8,
  .off_ashmem_misc_fops=0, .off_ashmem_fops=0x01449FB8,
  .off_ashmem_ioctl=0x00DFECB4, .off_ashmem_compat_ioctl=0x00DFED00,
  .off_ashmem_mmap=0x00DFED7C, .off_ashmem_open=0x00DFEDA0,
  .off_ashmem_release=0x00DFEE78, .off_ashmem_show_fdinfo=0x00DFF040,
  .off_configfs_read_iter=0x0053CC9C, .off_configfs_bin_write_iter=0x0053D248,
  .off_copy_splice_read=0x004B5E4C, .off_noop_llseek=0x0046181C,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x02551FD8, .off_slide_loggers_0_1=0x02551F28,
  .off_slide_boot_id=0x0281B1D8,
  .off_system_unbound_wq=0x01918250, .off_call_usermodehelper_exec_work=0x0010691C,
),
