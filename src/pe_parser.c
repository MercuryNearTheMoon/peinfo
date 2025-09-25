#include <stdlib.h>

#include "pe_parser.h"

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