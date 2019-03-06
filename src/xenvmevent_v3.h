// Copyright (c) 2018-2019 Bitdefender SRL, All rights reserved.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library.

#ifndef __XEN_PUBLIC_VM_EVENT_V3_H_INCLUDED__
#define __XEN_PUBLIC_VM_EVENT_V3_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

#include <xen/io/ring.h>

struct vm_event_regs_x86_v3 {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t dr7;
    uint64_t rip;
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    uint64_t msr_efer;
    uint64_t msr_star;
    uint64_t msr_lstar;
    uint64_t fs_base;
    uint64_t gs_base;
    uint32_t cs_arbytes;
    uint32_t _pad;
};

struct vm_event_regs_arm_v3 {
    uint64_t ttbr0;
    uint64_t ttbr1;
    uint64_t ttbcr;
    uint64_t pc;
    uint32_t cpsr;
    uint32_t _pad;
};

struct vm_event_mem_access_v3 {
    uint64_t gfn;
    uint64_t offset;
    uint64_t gla;   /* if flags has MEM_ACCESS_GLA_VALID set */
    uint32_t flags; /* MEM_ACCESS_* */
    uint32_t _pad;
};

struct vm_event_write_ctrlreg_v3 {
    uint32_t index;
    uint32_t _pad;
    uint64_t new_value;
    uint64_t old_value;
};

struct vm_event_singlestep_v3 {
    uint64_t gfn;
};

struct vm_event_debug_v3 {
    uint64_t gfn;
    uint32_t insn_length;
    uint8_t type;        /* HVMOP_TRAP_* */
    uint8_t _pad[3];
};

struct vm_event_mov_to_msr_v3 {
    uint64_t msr;
    uint64_t new_value;
    uint64_t old_value;
};

struct vm_event_desc_access_v3 {
    union {
        struct {
            uint32_t instr_info;         /* VMX: VMCS Instruction-Information */
            uint32_t _pad1;
            uint64_t exit_qualification; /* VMX: VMCS Exit Qualification */
        } vmx;
        struct {
            uint64_t exitinfo;           /* SVM: VMCB EXITINFO */
            uint64_t _pad2;
        } svm;
    } arch;
    uint8_t descriptor;                  /* VM_EVENT_DESC_* */
    uint8_t is_write;
    uint8_t _pad[6];
};

struct vm_event_cpuid_v3 {
    uint32_t insn_length;
    uint32_t leaf;
    uint32_t subleaf;
    uint32_t _pad;
};

struct vm_event_interrupt_x86_v3 {
    uint32_t vector;
    uint32_t type;
    uint32_t error_code;
    uint32_t _pad;
    uint64_t cr2;
};

struct vm_event_paging_v3 {
    uint64_t gfn;
    uint32_t p2mt;
    uint32_t flags;
};

struct vm_event_sharing_v3 {
    uint64_t gfn;
    uint32_t p2mt;
    uint32_t _pad;
};

struct vm_event_emul_read_data_v3 {
    uint32_t size;
    /* The struct is used in a union with vm_event_regs_x86. */
    uint8_t  data[sizeof(struct vm_event_regs_x86_v3) - sizeof(uint32_t)];
};

struct vm_event_emul_insn_data_v3 {
    uint8_t data[16]; /* Has to be completely filled */
};

typedef struct vm_event_st_v3 {
    uint32_t version;   /* VM_EVENT_INTERFACE_VERSION */
    uint32_t flags;     /* VM_EVENT_FLAG_* */
    uint32_t reason;    /* VM_EVENT_REASON_* */
    uint32_t vcpu_id;
    uint16_t altp2m_idx; /* may be used during request and response */
    uint16_t _pad[3];

    union {
        struct vm_event_paging_v3                mem_paging;
        struct vm_event_sharing_v3               mem_sharing;
        struct vm_event_mem_access_v3            mem_access;
        struct vm_event_write_ctrlreg_v3         write_ctrlreg;
        struct vm_event_mov_to_msr_v3            mov_to_msr;
        struct vm_event_desc_access_v3           desc_access;
        struct vm_event_singlestep_v3            singlestep;
        struct vm_event_debug_v3                 software_breakpoint;
        struct vm_event_debug_v3                 debug_exception;
        struct vm_event_cpuid_v3                 cpuid;
        union {
            struct vm_event_interrupt_x86_v3     x86;
        } interrupt;
    } u;

    union {
        union {
            struct vm_event_regs_x86_v3 x86;
            struct vm_event_regs_arm_v3 arm;
        } regs;

        union {
            struct vm_event_emul_read_data_v3 read;
            struct vm_event_emul_insn_data_v3 insn;
        } emul;
    } data;
} vm_event_request_v3_t, vm_event_response_v3_t;

DEFINE_RING_TYPES(vm_event_v3, vm_event_request_v3_t, vm_event_response_v3_t);

#ifdef __cplusplus
}
#endif

#endif // __XEN_PUBLIC_VM_EVENT_V3_H_INCLUDED__
