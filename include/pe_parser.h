#include "types.h"
#include "pe.h"
#include "pe_inspector.h"

IMAGE_DOS_HEADER *parse_IMAGE_DOS_HEADER(FILE *);
DOS_STUB *parse_DOS_STUB(FILE *, IMAGE_DOS_HEADER *);
PE_HEADER *parse_PE_HEADER(FILE *);