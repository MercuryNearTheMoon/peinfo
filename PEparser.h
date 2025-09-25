#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RESET "\033[0m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define WHITE "\033[37m"

#define BYTE_HEX_OUTPUT YELLOW "0x%02X" RESET
#define WORD_HEX_OUTPUT YELLOW "0x%04X" RESET
#define DWORD_HEX_OUTPUT YELLOW "0x%08X" RESET
#define LONG_HEX_OUTPUT DWORD_HEX_OUTPUT

#define MAGIC_MZ 0x5A4D
#define PE_SIGNATURE 0x00004550

#define MAX_FLAG_STR_LEN 512

#define UNRECOGNIZED RED "Unrecognized" RESET
#define RESERVED RED "Reserved" RESET
#define BYTES_STR BLUE "bytes" RESET

typedef uint8_t BYTE;   // 8-bit
typedef uint16_t WORD;  // 16-bit
typedef uint32_t DWORD; // 32-bit
typedef int32_t LONG;   // 32-bit signed

typedef struct {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    BYTE *code;
    size_t size;
} DOS_STUB;

typedef struct {
    WORD Machine; // cpu arch
    WORD NumberOfSections;
    DWORD TimeDateStamp; // timestamp (UTC)
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader; // Optional Header
    WORD Characteristics;
} COFF_HEADER;

typedef struct {
    WORD Magic;
    BYTE MajorLinkerVer;
    BYTE MinorLinkerVer;
    DWORD SizeOfCode;
    DWORD SizeOfInitedData;
    DWORD SizeOfUninitedData;
    DWORD AddrOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
} STD_COFF_FIELDS;

typedef struct {
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    // OS: OperatingSystem
    WORD MajorOSVersion;
    WORD MinorOSVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    // Ss: Subsystem
    WORD MajorSsVersion;
    WORD MinorSsVersion;
    DWORD Win32VersionValue; // Reversed, must be 0
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags; // Reversed, must be 0
    DWORD NumberOfRvaAndSizes;
} WINDOWS_SPECIFIC_FIELDS;

typedef struct {
    DWORD Signature;
    COFF_HEADER coffH;
    // Optional Headers
    STD_COFF_FIELDS coffF;
    WINDOWS_SPECIFIC_FIELDS winF;
    // ...
} PE_HEADER;

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
    // ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
    IMAGE_FILE_RELOCS_STRIPPED     = 0x0001,
    IMAGE_FILE_EXECUTABLE_IMAGE    = 0x0002,
    IMAGE_FILE_LINE_NUMS_STRIPPED  = 0x0004,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,

    IMAGE_FILE_AGGRESSIVE_WS_TRIM  = 0x0010,
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
    IMAGE_FILE_RESERVED            = 0x0040,
    IMAGE_FILE_BYTES_REVERSED_LO   = 0x0080,

    IMAGE_FILE_32BIT_MACHINE           = 0x0100,
    IMAGE_FILE_DEBUG_STRIPPED          = 0x0200,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
    IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800,

    IMAGE_FILE_SYSTEM            = 0x1000,
    IMAGE_FILE_DLL               = 0x2000,
    IMAGE_FILE_UP_SYSTEM_ONLY    = 0x4000,
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000

} IMAGE_CHARACTERISTICS;

const char *wordToChars(WORD);
const char *dwordToChars(DWORD);
const char *getMachineName(WORD);
const char *getCOFFMagicName(WORD);
const char *getSubsystemName(WORD);

char *timestampToLocalTime(DWORD);
char *getCharacteristicsFlags(WORD);
char *getDLLCharacteristicsFlags(WORD);

IMAGE_DOS_HEADER *parse_IMAGE_DOS_HEADER(FILE *);
DOS_STUB *parse_DOS_STUB(FILE *, IMAGE_DOS_HEADER *);
PE_HEADER *parse_PE_HEADER(FILE *);
uint32_t getMZFileSize(WORD, WORD);

void print_IMAGE_DOS_HEADER(IMAGE_DOS_HEADER *);
void print_DOS_STUB(DOS_STUB *);
void print_PE_HEADER(PE_HEADER *);