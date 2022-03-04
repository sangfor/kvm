/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/bits.h>
#include <linux/init.h>
#include <linux/bits.h>

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

#define TDX_HYPERCALL_STANDARD  0

#define TDX_HCALL_HAS_OUTPUT	BIT(0)

/*
 * SW-defined error codes.
 *
 * Bits 47:40 == 0xFF indicate Reserved status code class that never used by
 * TDX module.
 */
#define TDX_ERROR			_BITUL(63)
#define TDX_SW_ERROR			(TDX_ERROR | GENMASK_ULL(47, 40))
#define TDX_SEAMCALL_VMFAILINVALID	(TDX_SW_ERROR | _UL(0xFFFF0000))

#ifndef __ASSEMBLY__

#include <asm/processor.h>

/*
 * Used to gather the output registers values of the TDCALL and SEAMCALL
 * instructions when requesting services from the TDX module.
 *
 * This is a software only structure and not part of the TDX module/VMM ABI.
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/*
 * Used in __tdx_hypercall() to pass down and get back registers' values of
 * the TDCALL instruction when requesting services from the VMM.
 *
 * This is a software only structure and not part of the TDX module/VMM ABI.
 */
struct tdx_hypercall_args {
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);

/* Used to communicate with the TDX module */
u64 __tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		      struct tdx_module_output *out);

/* Used to request services from the VMM */
u64 __tdx_hypercall(struct tdx_hypercall_args *args, unsigned long flags);

/* Called from __tdx_hypercall() for unrecoverable failure */
void __tdx_hypercall_failed(void);

#else

static inline void tdx_early_init(void) { };

#endif /* CONFIG_INTEL_TDX_GUEST */

#ifdef CONFIG_INTEL_TDX_HOST
struct tdx_cpuid_config {
	u32	leaf;
	u32	sub_leaf;
	u32	eax;
	u32	ebx;
	u32	ecx;
	u32	edx;
} __packed;

#define TDSYSINFO_STRUCT_SIZE		1024
#define TDSYSINFO_STRUCT_ALIGNMENT	1024

struct tdsysinfo_struct {
	/* TDX-SEAM Module Info */
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor_version;
	u16	major_version;
	u8	reserved0[14];
	/* Memory Info */
	u16	max_tdmrs;
	u16	max_reserved_per_tdmr;
	u16	pamt_entry_size;
	u8	reserved1[10];
	/* Control Struct Info */
	u16	tdcs_base_size;
	u8	reserved2[2];
	u16	tdvps_base_size;
	u8	tdvps_xfam_dependent_size;
	u8	reserved3[9];
	/* TD Capabilities */
	u64	attributes_fixed0;
	u64	attributes_fixed1;
	u64	xfam_fixed0;
	u64	xfam_fixed1;
	u8	reserved4[32];
	u32	num_cpuid_config;
	/*
	 * The actual number of CPUID_CONFIG depends on above
	 * 'num_cpuid_config'.  The size of 'struct tdsysinfo_struct'
	 * is 1024B defined by TDX architecture.  Use a union with
	 * specific padding to make 'sizeof(struct tdsysinfo_struct)'
	 * equal to 1024.
	 */
	union {
		struct tdx_cpuid_config	cpuid_configs[0];
		u8			reserved5[892];
	};
} __packed __aligned(TDSYSINFO_STRUCT_ALIGNMENT);

void tdx_detect_cpu(struct cpuinfo_x86 *c);
int tdx_detect(void);
int tdx_init(void);
bool platform_has_tdx(void);
const struct tdsysinfo_struct *tdx_get_sysinfo(void);
#else
static inline void tdx_detect_cpu(struct cpuinfo_x86 *c) { }
static inline int tdx_detect(void) { return -ENODEV; }
static inline int tdx_init(void) { return -ENODEV; }
static inline bool platform_has_tdx(void) { return false; }
struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void) { return NULL; }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_TDX_H */
