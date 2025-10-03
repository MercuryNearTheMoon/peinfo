#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include "pe_inspector.h"
#include "utils.h"

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
    case COFF_MAGIC_PE32:
        return "PE32 Normal Executable";
    case COFF_MAGIC_ROM:
        return "ROM Image";
    case COFF_MAGIC_PE32P:
        return "PE32+ Executable";
    default:
        return UNRECOGNIZED;
    }
}

const char *getSubsystemName(WORD value) {
    // ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem
    switch (value) {
    case IMAGE_SUBSYSTEM_NATIVE:
        return "Device Drivers and Native Windows Processes";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        return "Windows GUI Subsystem";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        return "Windows Character Subsystem";
    case IMAGE_SUBSYSTEM_OS2_CUI:
        return "OS/2 Character Subsystem";
    case IMAGE_SUBSYSTEM_POSIX_CUI:
        return "Posix Character Subsystem";
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
        return "Native Win9x Driver";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        return "Windows CE";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        return "EFI App";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        return "EFI driver with Boot Services";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        return "EFI Driver with Run-Time Services";
    case IMAGE_SUBSYSTEM_EFI_ROM:
        return "EFI ROM Image";
    case IMAGE_SUBSYSTEM_XBOX:
        return "XBOX";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
        return "Windows Boot App";
    case IMAGE_SUBSYSTEM_UNKNOWN:
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

char *getSectionCharacteristicsFlags(DWORD c) {
    const char *alignBytes[] = {
        "Align data on 1-byte", "Align data on 2-byte", "Align data on 4-byte", "Align data on 8-byte", "Align data on 16-byte", "Align data on 32-byte", "Align data on 64-byte",
        "Align data on 128-byte", "Align data on 256-byte", "Align data on 512-byte", "Align data on 1024-byte", "Align data on 2048-byte", "Align data on 4096-byte", "Align data on 8192-byte"};
    // ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
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

    if (c & 0x00000000)
        APPEND_FLAG("");
    if (c & 0x00000001)
        APPEND_FLAG("");
    if (c & 0x00000002)
        APPEND_FLAG("");
    if (c & 0x00000004)
        APPEND_FLAG("");
    if (c & 0x00000008)
        APPEND_FLAG("NO PAD");
    if (c & 0x00000010)
        APPEND_FLAG("Contain Executable Code");
    if (c & 0x00000020)
        APPEND_FLAG("Contain Initialized Data");
    if (c & 0x00000040)
        APPEND_FLAG("Contain Uninitialized Data");
    if (c & 0x00000080)
        APPEND_FLAG("Enforce Check Code Integrity");
    if (c & 0x00000100)
        APPEND_FLAG(RESERVED);
    if (c & 0x00000200)
        APPEND_FLAG("Contain Comments");
    if (c & 0x00000400)
        APPEND_FLAG(RESERVED);
    if (c & 0x00000800)
        APPEND_FLAG("Not be Part of Image");
    if (c & 0x00001000)
        APPEND_FLAG("Contains COMDAT Data");
    if (c & 0x00002000)
        APPEND_FLAG("");
    if (c & 0x00004000)
        APPEND_FLAG("");
    if (c & 0x00008000)
        APPEND_FLAG("Contains Data Referenced by GP");
    if (c & 0x00010000)
        APPEND_FLAG("");
    if (c & 0x00020000)
        APPEND_FLAG(RESERVED);
    if (c & 0x00040000)
        APPEND_FLAG(RESERVED);
    if (c & 0x00080000)
        APPEND_FLAG(RESERVED);
    for (int i = 1; i < 0xf; i++) {
        if (c & (i << 20)) {
            APPEND_FLAG(alignBytes[i]);
            break;
        }
    }
    if (c & 0x0100000)
        APPEND_FLAG("Contains Extended Relocations");
    if (c & 0x0200000)
        APPEND_FLAG("Can be Discard");
    if (c & 0x0400000)
        APPEND_FLAG("Cannot be Cached");
    if (c & 0x0800000)
        APPEND_FLAG("Not Pageable");
    if (c & 0x10000000)
        APPEND_FLAG("Can be Shared");
    if (c & 0x20000000)
        APPEND_FLAG("Can be Executed");
    if (c & 0x40000000)
        APPEND_FLAG("Can be Read");
    if (c & 0x80000000)
        APPEND_FLAG("Can be written");

    if (first)
        strcat(FlagStr, "None"); // not any flag existed

#undef APPEND_FLAG
    return FlagStr;
}

char *getSectionName(BYTE *name) {
    if (!name)
        return NULL;

    char *result = (char *)malloc(9);
    if (!result)
        return NULL;

    memcpy(result, name, 8);
    result[8] = '\0';

    return result;
}

ByteStream *loadFile(FILE *fd) {
    if (!fd) return NULL;

    ByteStream *bs = calloc(1, sizeof(ByteStream));
    if (!bs) return NULL;

    if (fseek(fd, 0, SEEK_END) != 0) {
        free(bs);
        return NULL;
    }
    long fsize = ftell(fd);
    if (fsize < 0) {
        free(bs);
        return NULL;
    }
    rewind(fd);

    bs->size = (size_t)fsize;
    bs->base = malloc(bs->size);
    if (!bs->base) {
        free(bs);
        return NULL;
    }

    size_t nRead = fread(bs->base, 1, bs->size, fd);
    if (nRead != bs->size) {
        free(bs->base);
        free(bs);
        return NULL;
    }

    bs->cursor = bs->base;
    return bs;
}

size_t bsRead(void *out, size_t size, size_t nmemb, ByteStream *bs) {
    size_t bytesToRead = size * nmemb;
    size_t bytesLeft = bs->size - (size_t)(bs->cursor - bs->base);

    if (bytesLeft == 0) {
        return 0; // EOF
    }

    size_t bytesCanRead = (bytesToRead <= bytesLeft) ? bytesToRead : bytesLeft;

    memcpy(out, bs->cursor, bytesCanRead);
    bs->cursor += bytesCanRead;

    return bytesCanRead / size;
}

void bsFree(ByteStream *bs){
    if (bs) {
        free(bs->base);
        free(bs);
    }
}
