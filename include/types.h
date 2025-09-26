#pragma once
#include <stdint.h>
#include <stdio.h>

#define MAGIC_MZ 0x5A4D
#define PE_SIGNATURE 0x00004550

#define MAX_FLAG_STR_LEN 1024
#define MAX_DD_NUM 16

typedef uint8_t BYTE;     // 8-bit
typedef uint16_t WORD;    // 16-bit
typedef uint32_t DWORD;   // 32-bit
typedef int32_t LONG;     // 32-bit signed
typedef uint64_t QWORD;   // 64-bit
typedef QWORD ULONGLONNG; // 64-bit

typedef enum {
    IMAGE_MACHINE_UNKNOWN   = 0x0,    // Unknown
    IMAGE_MACHINE_AM33      = 0x1d3,  // Matsushita AM33
    IMAGE_MACHINE_AMD64     = 0x8664, // x64
    IMAGE_MACHINE_ARM       = 0x1c0,  // ARM little endian
    IMAGE_MACHINE_ARM64     = 0xaa64, // ARM64 little endian
    IMAGE_MACHINE_ARMNT     = 0x1c4,  // ARM Thumb-2 little endian
    IMAGE_MACHINE_EBC       = 0xebc,  // EFI byte code
    IMAGE_MACHINE_I386      = 0x14c,  // Intel 386
    IMAGE_MACHINE_IA64      = 0x200,  // Intel Itanium
    IMAGE_MACHINE_M32R      = 0x9041, // Mitsubishi M32R little endian
    IMAGE_MACHINE_MIPS16    = 0x266,  // MIPS16
    IMAGE_MACHINE_MIPSFPU   = 0x366,  // MIPS with FPU
    IMAGE_MACHINE_MIPSFPU16 = 0x466,  // MIPS16 with FPU
    IMAGE_MACHINE_POWERPC   = 0x1f0,  // PowerPC little endian
    IMAGE_MACHINE_POWERPCFP = 0x1f1,  // PowerPC with floating point
    IMAGE_MACHINE_R4000     = 0x166,  // MIPS little endian
    IMAGE_MACHINE_SH3       = 0x1a2,  // SH3 little endian
    IMAGE_MACHINE_SH3DSP    = 0x1a3,  // SH3 DSP
    IMAGE_MACHINE_SH4       = 0x1a6,  // SH4 little endian
    IMAGE_MACHINE_SH5       = 0x1a8,  // SH5
    IMAGE_MACHINE_THUMB     = 0x1c2,  // ARM Thumb
    IMAGE_MACHINE_WCEMIPSV2 = 0x169   // MIPS little-endian WCE v2
} IMAGE_MACHINE;

typedef enum {
    COFF_MAGIC_PE32  = 0x10B,
    COFF_MAGIC_ROM   = 0x107,
    COFF_MAGIC_PE32P = 0x20B
} COFF_MAGIC;

typedef enum {
    IMAGE_SUBSYSTEM_UNKNOWN                  = 0,
    IMAGE_SUBSYSTEM_NATIVE                   = 1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3,
    IMAGE_SUBSYSTEM_OS2_CUI                  = 5,
    IMAGE_SUBSYSTEM_POSIX_CUI                = 7,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12,
    IMAGE_SUBSYSTEM_EFI_ROM                  = 13,
    IMAGE_SUBSYSTEM_XBOX                     = 14,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 15
} IMAGE_SUBSYSTEM;
