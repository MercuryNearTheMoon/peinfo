#include "PEparser.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    FILE *fd = fopen(argv[1], "rb");
    if (fd == NULL) {
        fprintf(stderr, "Error: Can't open file %s\n", argv[1]);
        return 1;
    }

    IMAGE_DOS_HEADER *h = parse_IMAGE_DOS_HEADER(fd);
    if (h == NULL)
        return 1;
    print_IMAGE_DOS_HEADER(h);

    DOS_STUB *d = parse_DOS_STUB(fd, h);
    if (d == NULL) {
        free(h);
        return 1;
    }
    print_DOS_STUB(d);

    PE_HEADER *peH = parse_PE_HEADER(fd);
    if (peH == NULL) {
        free(h), free(d);
        return 1;
    }
    print_PE_HEADER(peH);

    free(h);
    free(d);
    free(peH);
    fclose(fd);
    return 0;
}

IMAGE_DOS_HEADER *parse_IMAGE_DOS_HEADER(FILE *fd) {
    IMAGE_DOS_HEADER *h = calloc(1, sizeof(IMAGE_DOS_HEADER));

    if (fread(h, sizeof(IMAGE_DOS_HEADER), 1, fd) != 1) {
        fprintf(stderr, "Parse Error: Failed to read IMAGE_DOS_HEADER\n");
        free(h);
        return NULL;
    }

    if (h->e_magic != MAGIC_MZ) {
        fprintf(stderr, "Parse Error: Invalid Magic Number 0x%04X\n", h->e_magic);
        free(h);
        return NULL;
    }

    return h;
}

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

void print_IMAGE_DOS_HEADER(IMAGE_DOS_HEADER *h) {
    puts("IMAGE_DOS_HEADER:");
    const char *magicStr = wordToChars(h->e_magic);

    printf("\tMagic: " WORD_HEX_OUTPUT "\t(%s)\n", h->e_magic, magicStr);
    printf("\tMZ file size: %d " BYTES_STR "\n", getMZFileSize(h->e_cp, h->e_cblp));
    printf("\tRelocation table offset: 0x%04X, Nums of entries: %d\n",
           h->e_lfarlc, h->e_crlc);
    printf("\tDOS header size: %d " BYTES_STR "\n", h->e_cparhdr * 16);
    printf("\tMZ DOS stub min memory size: %d " BYTES_STR "\n", h->e_minalloc * 16);
    printf("\tMZ DOS stub max memory size: %d " BYTES_STR "\n", h->e_maxalloc * 16);
    printf("\tMS DOS init stack addr: 0x%04X (SS:SP = 0x%04X:0x%04X)\n",
           h->e_ss * 16 + h->e_sp, h->e_ss, h->e_sp);
    printf("\tDOS EXE stub checksum: " WORD_HEX_OUTPUT "\n", h->e_csum);
    printf("\tMS DOS initial IP: 0x%04X (CS: 0x%04X, entry=0x%04X)\n",
           h->e_ip, h->e_cs, h->e_cs * 16 + h->e_ip);
    printf("\tOverlay number: %d\n", h->e_ovno);
    printf("\t" RESERVED " part 1(4 WORD): " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT "\n",
           h->e_res[0], h->e_res[1], h->e_res[2], h->e_res[3]);
    printf("\tOEM ID: 0x%04X\n", h->e_oemid);
    printf("\tOEM Info: 0x%04X\n", h->e_oeminfo);
    printf("\t" RESERVED " part 2(10 WORD): " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT " " WORD_HEX_OUTPUT "\n",
           h->e_res2[0], h->e_res2[1], h->e_res2[2], h->e_res2[3], h->e_res2[4],
           h->e_res2[5], h->e_res2[6], h->e_res2[7], h->e_res2[8], h->e_res2[9]);
    printf("\tNT Headers offset: " LONG_HEX_OUTPUT "\n", h->e_lfanew);

    putchar('\n');
}

DOS_STUB *parse_DOS_STUB(FILE *fd, IMAGE_DOS_HEADER *h) {
    DOS_STUB *d = calloc(1, sizeof(DOS_STUB));

    d->size = h->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    if (d->size == 0) {
        fprintf(stderr, "Parse Error: Failed to read DOS_STUB\n");
        free(d);
        return NULL;
    }

    d->code = calloc(d->size, sizeof(BYTE));
    if (fread(d->code, d->size, 1, fd) != 1) {
        fprintf(stderr, "Parse Error: Failed to read DOS_STUB\n");
        free(d);
        return NULL;
    }

    return d;
}

void print_DOS_STUB(DOS_STUB *d) {
    puts("DOS_STUB:");
    printf("\t");
    for (int i = 0; i < d->size; i++) {
        printf(BYTE_HEX_OUTPUT " ", d->code[i]);
        if ((i + 1) % 16 == 0)
            printf("\n\t");
    }

    puts("\n");
}

PE_HEADER *parse_PE_HEADER(FILE *fd) {
    PE_HEADER *peH = calloc(1, sizeof(PE_HEADER));
    if (fread(peH, sizeof(PE_HEADER), 1, fd) != 1) {
        fprintf(stderr, "Parse Error: Failed to read PE_HEADER\n");
        free(peH);
        return NULL;
    }

    if (peH->Signature != PE_SIGNATURE) {
        fprintf(stderr, "Parse Error: Invaild PE Signature " DWORD_HEX_OUTPUT "\n", peH->Signature);
        free(peH);
        return NULL;
    }

    return peH;
}

void print_PE_HEADER(PE_HEADER *peH) {
    puts("PE HEADER:");

    const char *signatureStr = dwordToChars(peH->Signature);
    printf("\tPE Signature: " DWORD_HEX_OUTPUT "\t(%s)\n", peH->Signature, signatureStr);
    // COFF header
    puts("\tCOFF HEADER:");
    COFF_HEADER *coffH = &peH->coffH;

    const char *machineName = getMachineName(coffH->Machine);
    printf("\t\tMachine: " WORD_HEX_OUTPUT "\t(%s)\n", coffH->Machine, machineName);

    printf("\t\tNums of Sections: %d\n", coffH->NumberOfSections);

    char *localTime = timestampToLocalTime(coffH->TimeDateStamp);
    printf("\t\tFile Created at: " DWORD_HEX_OUTPUT "\t(%s)\n", coffH->TimeDateStamp, localTime);
    free(localTime);

    printf("\t\tPoint to SymTable: " DWORD_HEX_OUTPUT "\n", coffH->PointerToSymbolTable);
    printf("\t\tNums of SymTable: " DWORD_HEX_OUTPUT "\n", coffH->NumberOfSymbols);

    printf("\t\tSize of Optional Header: " WORD_HEX_OUTPUT "\n", coffH->SizeOfOptionalHeader);

    char *flagStr = getCharacteristicsFlags(coffH->Characteristics);
    printf("\t\tCharacteristics: " WORD_HEX_OUTPUT "\t(%s)\n", coffH->Characteristics, flagStr);
    free(flagStr);

    // Optional Headers
    //  Standard COFF Fields
    puts("\tSTANDARD COFF FIELDS:");
    STD_COFF_FIELDS *coffF       = &peH->coffF;
    const char *coffF_magic_name = getCOFFMagicName(coffF->Magic);
    printf("\t\tMagic: " WORD_HEX_OUTPUT "\t(%s)\n", coffF->Magic, coffF_magic_name);

    printf("\t\tLinker Version: %d.%d\n", coffF->MajorLinkerVer, coffF->MinorLinkerVer);

    printf("\t\tSize of Code: %d " BYTES_STR "\n", coffF->SizeOfCode);

    printf("\t\tSize of Initialized data: %d " BYTES_STR "\n", coffF->SizeOfInitedData);
    printf("\t\tSize of Uninitialized data (.bss): %d " BYTES_STR "\n", coffF->SizeOfUninitedData);

    printf("\t\tAddress of Entry Point:" DWORD_HEX_OUTPUT "\n", coffF->AddrOfEntryPoint);

    printf("\t\tAddress of Beginning-of-Code Section:" DWORD_HEX_OUTPUT "\n", coffF->BaseOfCode);
    printf("\t\tAddress of Beginning-of-Data Section:" DWORD_HEX_OUTPUT "\n", coffF->BaseOfData);

    //  Windows-Specific Fields
    WINDOWS_SPECIFIC_FIELDS *winF = &peH->winF;
    puts("\tWINDOWS SPECIFIC FIELDS:");

    printf("\t\tImage Base: " DWORD_HEX_OUTPUT "\n", winF->ImageBase);

    printf("\t\tSection Alignment: %d " BYTES_STR "\n", winF->SectionAlignment);
    printf("\t\tFile Alignment: %d " BYTES_STR "\n", winF->FileAlignment);

    printf("\t\tOperating System Version: %d.%d\n", winF->MajorOSVersion, winF->MinorOSVersion);

    printf("\t\tSubsystem Version: %d.%d\n", winF->MajorSsVersion, winF->MinorSsVersion);

    printf("\t\tImage Version: %d.%d\n", winF->MajorImageVersion, winF->MinorImageVersion);

    printf("\t\tWin32 Version Value: " DWORD_HEX_OUTPUT "\t(" RESERVED ")\n", winF->Win32VersionValue);

    printf("\t\tSize of Image: %d " BYTES_STR "\n", winF->SizeOfImage);

    printf("\t\tSize of Headers: %d " BYTES_STR "\n", winF->SizeOfHeaders);

    printf("\t\tChecksum: " DWORD_HEX_OUTPUT "\n", winF->CheckSum);

    printf("\t\tSubsystem: %d\t(%s)\n", winF->Subsystem, getSubsystemName(winF->Subsystem));

    char *DlCharFlagsStr = getDLLCharacteristicsFlags(winF->DllCharacteristics);
    printf("\t\tDLL Characteristics: " WORD_HEX_OUTPUT "\t(%s)\n", winF->DllCharacteristics, DlCharFlagsStr);
    free(DlCharFlagsStr);

    printf("\t\tSize of Stack Reserved: %d " BYTES_STR "\t"
           "Size of Stack Commited: %d " BYTES_STR "\n",
           winF->SizeOfStackReserve, winF->SizeOfStackCommit);

    printf("\t\tSize of Heap Reserved: %d " BYTES_STR "\tSize of Heap Commited: %d " BYTES_STR "\n", winF->SizeOfHeapReserve, winF->SizeOfHeapCommit);

    printf("\t\tLoader Flags: " DWORD_HEX_OUTPUT " (" RESERVED ")\n", winF->LoaderFlags);

    printf("\t\tNums of Data Directory: %d\n", winF->NumberOfRvaAndSizes);

    putchar('\n');
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
