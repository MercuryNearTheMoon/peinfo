#include "types.h"

const char *wordToChars(WORD);
const char *dwordToChars(DWORD);
const char *getMachineName(WORD);
const char *getCOFFMagicName(WORD);
const char *getSubsystemName(WORD);


char *timestampToLocalTime(DWORD);
char *getCharacteristicsFlags(WORD);
char *getDLLCharacteristicsFlags(WORD);

uint32_t getMZFileSize(WORD, WORD);