#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"
#include "pe_inspector.h"

const char *wordToChars(WORD w) {
    char *result = malloc(3);
    // little-edian
    result[0] = (char)(w & 0xFF);
    result[1] = (char)((w >> 8) & 0xFF);
    result[2] = '\0';
    return result;
}

const char *dwordToChars(DWORD w) {
    char *result = malloc(5);
    // little-edian
    result[0] = (char)(w & 0xFF);
    result[1] = (char)((w >> 8 * 1) & 0xFF);
    result[2] = (char)((w >> 8 * 2) & 0xFF);
    result[3] = (char)((w >> 8 * 3) & 0xFF);
    result[4] = '\0';
    return result;
}

uint32_t getMZFileSize(WORD cp, WORD cblp) {
    if (cblp == 0)
        return cp * 512;
    else
        return (cp - 1) * 512 + cblp;
}

const char *getMachineName(WORD machine) {
    switch (machine) {
    case IMAGE_MACHINE_UNKNOWN:
        return "Unknown";
    case IMAGE_MACHINE_AM33:
        return "Matsushita AM33";
    case IMAGE_MACHINE_AMD64:
        return "x64";
    case IMAGE_MACHINE_ARM:
        return "ARM (little endian)";
    case IMAGE_MACHINE_ARM64:
        return "ARM64 (little endian)";
    case IMAGE_MACHINE_ARMNT:
        return "ARM Thumb-2 (little endian)";
    case IMAGE_MACHINE_EBC:
        return "EFI byte code";
    case IMAGE_MACHINE_I386:
        return "Intel 386";
    case IMAGE_MACHINE_IA64:
        return "Intel Itanium";
    case IMAGE_MACHINE_M32R:
        return "Mitsubishi M32R (little endian)";
    case IMAGE_MACHINE_MIPS16:
        return "MIPS16";
    case IMAGE_MACHINE_MIPSFPU:
        return "MIPS with FPU";
    case IMAGE_MACHINE_MIPSFPU16:
        return "MIPS16 with FPU";
    case IMAGE_MACHINE_POWERPC:
        return "PowerPC (little endian)";
    case IMAGE_MACHINE_POWERPCFP:
        return "PowerPC with floating point";
    case IMAGE_MACHINE_R4000:
        return "MIPS (little endian)";
    case IMAGE_MACHINE_SH3:
        return "SH3 (little endian)";
    case IMAGE_MACHINE_SH3DSP:
        return "SH3 DSP";
    case IMAGE_MACHINE_SH4:
        return "SH4 (little endian)";
    case IMAGE_MACHINE_SH5:
        return "SH5";
    case IMAGE_MACHINE_THUMB:
        return "ARM Thumb";
    case IMAGE_MACHINE_WCEMIPSV2:
        return "MIPS little-endian WCE v2";
    default:
        return UNRECOGNIZED;
    }
}

char *timestampToLocalTime(DWORD ts) {
    time_t t         = (time_t)ts;
    struct tm *local = localtime(&t);

    char tmp[32];
    strftime(tmp, sizeof(tmp), "%a %b %d %H:%M:%S %Y", local); // Fri Sep 19 16:16:57 2025

    char *result = malloc(strlen(tmp) + 1);
    strcpy(result, tmp);
    return result;
}

char *getCharacteristicsFlags(WORD c) {
    char *FlagStr = calloc(MAX_FLAG_STR_LEN, sizeof(char));
    if (!FlagStr)
        return NULL;

    int first = 1;
#define APPEND_FLAG(str)            \
    do {                            \
        if (!first)                 \
            strcat(FlagStr, " | "); \
        else                        \
            first = 0;              \
        strcat(FlagStr, str);       \
    } while (0)

    if (c & 0x0001)
        APPEND_FLAG("Relocation info stripped");
    if (c & 0x0002)
        APPEND_FLAG("Executable Image");
    if (c & 0x0004)
        APPEND_FLAG("Line numbers stripped");
    if (c & 0x0008)
        APPEND_FLAG("Local symbols stripped");
    if (c & 0x0010)
        APPEND_FLAG("Aggressively trim WS");
    if (c & 0x0020)
        APPEND_FLAG("Large address aware");
    if (c & 0x0040)
        APPEND_FLAG(RESERVED);
    if (c & 0x0080)
        APPEND_FLAG("Bytes reversed LO");
    if (c & 0x0100)
        APPEND_FLAG("32-bit machine");
    if (c & 0x0200)
        APPEND_FLAG("Debug info stripped");
    if (c & 0x0400)
        APPEND_FLAG("Removable run from swap");
    if (c & 0x0800)
        APPEND_FLAG("Net run from swap");
    if (c & 0x1000)
        APPEND_FLAG("System file");
    if (c & 0x2000)
        APPEND_FLAG("DLL");
    if (c & 0x4000)
        APPEND_FLAG("UP system only");
    if (c & 0x8000)
        APPEND_FLAG("Bytes reversed HI");

    if (first)
        strcat(FlagStr, "None"); // not any flag existed

#undef APPEND_FLAG
    return FlagStr;
}

const char *getCOFFMagicName(WORD Magic) {
    // ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
    switch (Magic) {
    case 0x10B:
        return "PE32 Normal Executable";
    case 0x107:
        return "ROM Image";
    case 0x20B:
        return "PE32+ Executable";
    default:
        return UNRECOGNIZED;
    }
}

const char *getSubsystemName(WORD value) {
    // ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem
    switch (value) {
    case 1:
        return "Device Drivers and Native Windows Processes";
    case 2:
        return "Windows GUI Subsystem";
    case 3:
        return "Windows Character Subsystem";
    case 5:
        return "OS/2 Character Subsystem";
    case 7:
        return "Posix Character Subsystem";
    case 8:
        return "Native Win9x Driver";
    case 9:
        return "Windows CE";
    case 10:
        return "EFI App";
    case 11:
        return "EFI driver with Boot Services";
    case 12:
        return "EFI Driver with Run-Time Services";
    case 13:
        return "EFI ROM Image";
    case 14:
        return "XBOX";
    case 15:
        return "Windows Boot App";
    case 0:
    default:
        return "unknown subsystem";
    }
}

char *getDLLCharacteristicsFlags(WORD c) {
    // ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics
    char *FlagStr = calloc(MAX_FLAG_STR_LEN, sizeof(char));
    if (!FlagStr)
        return NULL;

    int first = 1;
#define APPEND_FLAG(str)            \
    do {                            \
        if (!first)                 \
            strcat(FlagStr, " | "); \
        else                        \
            first = 0;              \
        strcat(FlagStr, str);       \
    } while (0)

    if (c & 0x0001)
        APPEND_FLAG("");
    if (c & 0x0002)
        APPEND_FLAG("");
    if (c & 0x0004)
        APPEND_FLAG("");
    if (c & 0x0008)
        APPEND_FLAG("");
    if (c & 0x0010)
        APPEND_FLAG("");
    if (c & 0x0020)
        APPEND_FLAG("Support High Entropy ASLR");
    if (c & 0x0040)
        APPEND_FLAG("Enable RELO");
    if (c & 0x0080)
        APPEND_FLAG("Enforce Check Code Integrity");
    if (c & 0x0100)
        APPEND_FLAG("Enable NX");
    if (c & 0x0200)
        APPEND_FLAG("NOT Support SxS");
    if (c & 0x0400)
        APPEND_FLAG("NO SEH");
    if (c & 0x0800)
        APPEND_FLAG("NO BIND");
    if (c & 0x1000)
        APPEND_FLAG("Required AppContainer");
    if (c & 0x2000)
        APPEND_FLAG("WDM");
    if (c & 0x4000)
        APPEND_FLAG("Enable CFG");
    if (c & 0x8000)
        APPEND_FLAG("Terminal Services Aware");

    if (first)
        strcat(FlagStr, "None"); // not any flag existed

#undef APPEND_FLAG
    return FlagStr;
}