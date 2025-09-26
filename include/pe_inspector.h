#pragma once
#include "pe.h"

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
#define QWORD_HEX_OUTPUT YELLOW "0x%lX" RESET
#define ULONGLONG_HEX_OUTPUT QWORD_HEX_OUTPUT


#define UNRECOGNIZED RED "Unrecognized" RESET
#define RESERVED RED "Reserved" RESET
#define BYTES_STR BLUE "bytes" RESET

void print_IMAGE_DOS_HEADER(IMAGE_DOS_HEADER *);
void print_DOS_STUB(DOS_STUB *);
void print_PE_HEADER(PE_HEADER *);
void printDataDirectories(IMAGE_DATA_DIRECTORY *);

void _print_PE_OPTIONAL_HEADER_32(OPTIONAL_PE_HEADER_32 *);
void _print_PE_OPTIONAL_HEADER_64(OPTIONAL_PE_HEADER_64 *);
