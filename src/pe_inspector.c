#include <stdlib.h>
#include <stdio.h>

#include "pe_inspector.h"
#include "utils.h"

const char *DataDirectoryNames[16] = {
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug Directory",
    "Architecture Data",
    "Global Ptr",
    "TLS Table",
    "Load Config Table",
    "Bound Import",
    "IAT",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved"};

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

void print_DOS_STUB(DOS_STUB *d) {
    puts("DOS_STUB:");
    printf("\t");
    for (size_t i = 0; i < d->size; i++) {
        printf(BYTE_HEX_OUTPUT " ", d->code[i]);
        if ((i + 1) % 16 == 0)
            printf("\n\t");
    }

    puts("\n");
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

    //  Data Directories
    IMAGE_DATA_DIRECTORY *dd = peH->dd;
    puts("\tData Directories:");
    printDataDirectories(dd);

    putchar('\n');
}

void printDataDirectories(IMAGE_DATA_DIRECTORY *dd) {
    printf("\t\t%-4s  %-25s  %-10s  %-10s\n", "Idx", "Name", "RVA", "Size");

    for (DWORD i = 0; i < MAX_DD_NUM; i++) {
        const char *name = i < MAX_DD_NUM ? DataDirectoryNames[i] : "Unknown";
        printf("\t\t%-4u  %-25s  " DWORD_HEX_OUTPUT "  %10u\n",
               i, name, dd[i].VirtualAddress, dd[i].Size);
    }
}