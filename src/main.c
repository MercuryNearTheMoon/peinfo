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
    FILE *fd = fopen(argv[1], "rb");
    if (!fd) {
        fprintf(stderr, "Error: Can't open file %s\n", argv[1]);
        return 1;
    }

    ByteStream *bs = loadFile(fd);
    fclose(fd);
    if (!bs) {
        fprintf(stderr, "Error: Failed to load file %s\n", argv[1]);
        return 1;
    }

    IMAGE_DOS_HEADER *h = parse_IMAGE_DOS_HEADER(bs);
    if (h == NULL)
        return 1;
    print_IMAGE_DOS_HEADER(h);

    DOS_STUB *d = parse_DOS_STUB(bs, h);
    if (d == NULL) {
        free(h);
        return 1;
    }
    print_DOS_STUB(d);

    PE_HEADER *peH = parse_PE_HEADER(bs);
    if (peH == NULL) {
        free(h), free(d);
        return 1;
    }
    print_PE_HEADER(peH);

    WORD numsOfSections = peH->coffH.NumberOfSections;
    SECTIONS_HEADERS *sHs = parese_SECTIONS_HEADERS(bs, numsOfSections);
    if (sHs == NULL) {
        free(h), free(d), free(peH->optHeader);
        free(peH);
        return 1;
    }
    print_SECTIONS_HEADERS(sHs, numsOfSections);
    
    free(h);
    free(d);
    free(peH->optHeader);
    free(peH);
    for (int i=0;i<numsOfSections;i++){
        free(sHs[i]);
    }
    free(sHs);
    return 0;
}
