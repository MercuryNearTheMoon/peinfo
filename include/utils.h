#include "types.h"
#include "stdbool.h"

const char *wordToChars(WORD);
const char *dwordToChars(DWORD);
const char *getMachineName(WORD);
const char *getCOFFMagicName(WORD);
const char *getSubsystemName(WORD);

char *timestampToLocalTime(DWORD);
char *getCharacteristicsFlags(WORD);
char *getDLLCharacteristicsFlags(WORD);
char *getSectionCharacteristicsFlags(DWORD);
char *getSectionName(BYTE *);

uint32_t getMZFileSize(WORD, WORD);

ByteStream *loadFile(FILE *);