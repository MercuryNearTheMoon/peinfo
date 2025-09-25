#include <stdio.h>
#include <stdlib.h>

#include "pe_parser.h"
#include "pe.h"
#include "pe_inspector.h"

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




