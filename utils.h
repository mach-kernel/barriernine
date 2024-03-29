#include <Carbon.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef enum LogLevel {
	ERROR,
	INFO,
	TRACE
} LogLevel;

const char *logLevelName(LogLevel level);

typedef struct LogConf {
	LogLevel level;
} LogConf;

int loggerf(LogLevel level, const char *fmt, ...);

int pstrcmp(Str255 a, Str255 b);
int pstrstr(Str255 a, Str255 b);
char *pstr2cstr(Str255 in);
char *cstr2pstr(char *cstr);