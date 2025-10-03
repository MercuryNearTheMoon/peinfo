#include "types.h"
#include "pe.h"
#include "pe_inspector.h"

IMAGE_DOS_HEADER *parse_IMAGE_DOS_HEADER(ByteStream *);
DOS_STUB *parse_DOS_STUB(ByteStream *, IMAGE_DOS_HEADER *);
PE_HEADER *parse_PE_HEADER(ByteStream *);
SECTIONS_HEADER *parese_SECTIONS_HEADER(ByteStream *);
SECTIONS_HEADERS *parese_SECTIONS_HEADERS(ByteStream *, WORD);