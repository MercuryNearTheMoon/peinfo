#include <stdio.h>
#include <stdlib.h>

#include "pe.h"
#include "pe_inspector.h"
#include "pe_parser.h"
#include "utils.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    FILE *fd              = NULL;
    ByteStream *bs        = NULL;
    IMAGE_DOS_HEADER *h   = NULL;
    DOS_STUB *d           = NULL;
    PE_HEADER *peH        = NULL;
    SECTIONS_HEADERS *sHs = NULL;
    WORD numsOfSections   = 0;

    fd = fopen(argv[1], "rb");
    if (!fd) {
        fprintf(stderr, "Error: Can't open file %s\n", argv[1]);
        return 1;
    }

    bs = loadFile(fd);
    fclose(fd);
    if (!bs) {
        fprintf(stderr, "Error: Failed to load file %s\n", argv[1]);
        goto cleanup;
    }

    h = parse_IMAGE_DOS_HEADER(bs);
    if (!h)
        goto cleanup;
    print_IMAGE_DOS_HEADER(h);

    d = parse_DOS_STUB(bs, h);
    if (!d)
        goto cleanup;
    print_DOS_STUB(d);

    peH = parse_PE_HEADER(bs);
    if (!peH)
        goto cleanup;
    print_PE_HEADER(peH);

    numsOfSections = peH->coffH.NumberOfSections;
    sHs            = parese_SECTIONS_HEADERS(bs, numsOfSections);
    if (!sHs)
        goto cleanup;
    print_SECTIONS_HEADERS(sHs, numsOfSections);

cleanup:
    if (h)
        free(h);
    if (d)
        free(d);
    if (peH) {
        if (peH->optHeader)
            free(peH->optHeader);
        free(peH);
    }
    if (sHs) {
        for (int i = 0; i < numsOfSections; i++) {
            if (sHs[i])
                free(sHs[i]);
        }
        free(sHs);
    }
    if (bs)
        bsFree(bs);

    return 0;
}
