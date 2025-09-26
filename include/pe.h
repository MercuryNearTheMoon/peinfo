#pragma once
#include "types.h"
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
} STD_COFF_FIELDS_32;

typedef struct {
    WORD Magic;
    BYTE MajorLinkerVer;
    BYTE MinorLinkerVer;
    DWORD SizeOfCode;
    DWORD SizeOfInitedData;
    DWORD SizeOfUninitedData;
    DWORD AddrOfEntryPoint;
    DWORD BaseOfCode;
} STD_COFF_FIELDS_64;


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
} WINDOWS_SPECIFIC_FIELDS_32;

typedef struct {
    QWORD ImageBase;
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
    QWORD SizeOfStackReserve;
    QWORD SizeOfStackCommit;
    QWORD SizeOfHeapReserve;
    QWORD SizeOfHeapCommit;
    DWORD LoaderFlags; // Reversed, must be 0
    DWORD NumberOfRvaAndSizes;
} WINDOWS_SPECIFIC_FIELDS_64;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    DWORD Signature;
    COFF_HEADER coffH;
    // Optional Headers
    void *optHeader;
} PE_HEADER;

typedef struct {
    STD_COFF_FIELDS_32 coffF;
    WINDOWS_SPECIFIC_FIELDS_32 winF;
    IMAGE_DATA_DIRECTORY dd[16];
} OPTIONAL_PE_HEADER_32;

typedef struct {
    STD_COFF_FIELDS_64 coffF;
    WINDOWS_SPECIFIC_FIELDS_64 winF;
    IMAGE_DATA_DIRECTORY dd[16];
} OPTIONAL_PE_HEADER_64;
