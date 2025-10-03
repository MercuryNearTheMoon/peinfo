#include <stdlib.h>

#include "pe_parser.h"
#include "utils.h"

IMAGE_DOS_HEADER *parse_IMAGE_DOS_HEADER(ByteStream *bs) {
    IMAGE_DOS_HEADER *h = calloc(1, sizeof(IMAGE_DOS_HEADER));

    if (bsRead(h, sizeof(IMAGE_DOS_HEADER), 1, bs) != 1) {
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

DOS_STUB *parse_DOS_STUB(ByteStream *bs, IMAGE_DOS_HEADER *h) {
    DOS_STUB *d = calloc(1, sizeof(DOS_STUB));

    d->size = h->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    if (d->size == 0) {
        fprintf(stderr, "Parse Error: Failed to read DOS_STUB\n");
        free(d);
        return NULL;
    }

    d->code = calloc(d->size, sizeof(BYTE));
    if (bsRead(d->code, d->size, 1, bs) != 1) {
        fprintf(stderr, "Parse Error: Failed to read DOS_STUB\n");
        free(d);
        return NULL;
    }

    return d;
}

PE_HEADER *parse_PE_HEADER(ByteStream *bs) {
    PE_HEADER *peH = calloc(1, sizeof(PE_HEADER));
    if (bsRead(peH,
              sizeof(PE_HEADER) - sizeof(void *), // not to read optHeader
              1, bs) != 1) {
        fprintf(stderr, "Parse Error: Failed to read PE_HEADER\n");
        free(peH);
        return NULL;
    }

    if (peH->Signature != PE_SIGNATURE) {
        fprintf(stderr,
                "Parse Error: Invalid PE Signature " DWORD_HEX_OUTPUT "\n",
                peH->Signature);
        free(peH);
        return NULL;
    }

    WORD magic;
    if (bsRead(&magic, sizeof(magic), 1, bs) != 1) {
        fprintf(stderr, "Parse Error: Failed to read Magic in Optional Header Standard Fields\n");
        free(peH);
        return NULL;
    }

    void *opt = NULL;
    if (magic == COFF_MAGIC_PE32) {
        OPTIONAL_PE_HEADER_32 *opt32 = (OPTIONAL_PE_HEADER_32 *)calloc(1, sizeof(OPTIONAL_PE_HEADER_32));
        opt32->coffF.Magic           = magic;

        if (bsRead(&opt32->coffF.MajorLinkerVer,
                  sizeof(STD_COFF_FIELDS_32) - sizeof(WORD), // magic has been read
                  1, bs) != 1) {
            fprintf(stderr, "Parse Error: Failed to read STD_COFF_FIELDS_32\n");
            free(opt32);
            free(peH);
            return NULL;
        }

        if (bsRead(&opt32->winF, sizeof(WINDOWS_SPECIFIC_FIELDS_32), 1, bs) != 1) {
            fprintf(stderr, "Parse Error: Failed to read WINDOWS_SPECIFIC_FIELDS_32\n");
            free(opt32);
            free(peH);
            return NULL;
        }

        if (bsRead(opt32->dd, sizeof(IMAGE_DATA_DIRECTORY) * 16, 1, bs) != 1) {
            fprintf(stderr, "Parse Error: Failed to read IMAGE_DATA_DIRECTORY array\n");
            free(opt32);
            free(peH);
            return NULL;
        }

        opt = (void *)opt32;
    } else if (magic == COFF_MAGIC_PE32P) {
        OPTIONAL_PE_HEADER_64 *opt64 = (OPTIONAL_PE_HEADER_64 *)calloc(1, sizeof(OPTIONAL_PE_HEADER_64));
        opt64->coffF.Magic           = magic;

        if (bsRead(&opt64->coffF.MajorLinkerVer,
                  sizeof(STD_COFF_FIELDS_64) - sizeof(WORD),
                  1, bs) != 1) {
            fprintf(stderr, "Parse Error: Failed to read STD_COFF_FIELDS_64\n");
            free(opt64);
            free(peH);
            return NULL;
        }

        if (bsRead(&opt64->winF, sizeof(WINDOWS_SPECIFIC_FIELDS_64), 1, bs) != 1) {
            fprintf(stderr, "Parse Error: Failed to read WINDOWS_SPECIFIC_FIELDS_64\n");
            free(opt64);
            free(peH);
            return NULL;
        }

        if (bsRead(opt64->dd, sizeof(IMAGE_DATA_DIRECTORY) * 16, 1, bs) != 1) {
            fprintf(stderr, "Parse Error: Failed to read IMAGE_DATA_DIRECTORY turísticaarray\n");
            free(opt64);
            free(peH);
            return NULL;
        }

        opt = (void *)opt64;
    } else if(magic == COFF_MAGIC_ROM){
        opt = NULL;    // Only PE32 and PE32+ have Optional Header
    } else {
        fprintf(stderr,
                "Parse Error: " UNRECOGNIZED " Magic " WORD_HEX_OUTPUT " in Optional Header Standard Fields\n",
                magic);
        free(peH);
        return NULL;
    }

    peH->optHeader = opt;
    return peH;
}

SECTIONS_HEADER *parese_SECTIONS_HEADER(ByteStream *bs){
    SECTIONS_HEADER *sH = calloc(1, sizeof(SECTIONS_HEADER));
    if (bsRead(sH, sizeof(SECTIONS_HEADER), 1, bs)!=1){
        fprintf(stderr, "Parse Error: Failed to parse SECTIONS_HEADER");
        return NULL;
    }
    
    return sH;
}

SECTIONS_HEADERS *parese_SECTIONS_HEADERS(ByteStream *bs, WORD numsOfSections){
    SECTIONS_HEADERS *sHs = calloc(numsOfSections, sizeof(SECTIONS_HEADER));
    for (int i=0;i<numsOfSections;i++)
        sHs[i] = parese_SECTIONS_HEADER(bs);
    
    return sHs;
}