#include "utils.h"

static LogConf logConf = {
	TRACE
};

const char *logLevelName(LogLevel level) {
	switch (level) {
		case TRACE:
			return "TRACE";
		case INFO:
			return "INFO ";
		case ERROR: 
			return "ERROR";
	}
	return "";
}

int loggerf(LogLevel level, const char *fmt, ...) {
	time_t localTime;
	struct tm *now;
	char timestr[100];
	int ret;
	va_list varargs;
	
	if (level > logConf.level) return 0;
	
	localTime = time(NULL);
	now = localtime(&localTime);
	va_start(varargs, fmt);
	strftime(timestr, sizeof(timestr), "%F %T", now);
	
	printf("%s %s - ", logLevelName(level), timestr);
	ret = vprintf(fmt, varargs);
	printf("\n");
	return ret;
}

// i kind of like these strings
int pstrcmp(Str255 a, Str255 b) {
	unsigned char alen, blen, i;
	
	alen = *a;
	blen = *b;
	
	if (alen != blen) return (alen > blen) ? 1 : -1;
	
	for (i=0; i<alen; ++i) {
		if (a[i] == b[i]) continue;
		return (a[i] > b[i]) ? 1 : -1;
	}
	
	return 0;
}

int pstrstr(Str255 a, Str255 b) {
	char match;
	int i, j = 0;
	if (b[0] > a[0]) return 0;
	
	for (i=1; i<=a[0]; ++i) {
		match = false;
		for (j=1; j<=b[0]; ++j) {
			match = a[i+j-1] == b[j];
			if (!match) break;
		}
		if (match) return 1;
	}
	
	return 0;
}

char *pstr2cstr(Str255 in) {
	unsigned char len;
	char *cstr;
	len = *(in++);
	//if (len > 255) return NULL;
	cstr = calloc(len + 1, sizeof(char));
	memcpy(cstr, in, len);
	return cstr;
}

char *cstr2pstr(char *cstr) {
	char *pstr;
	int len = strlen(cstr);
	if (len > 255) return NULL;
	pstr = calloc(len + 1, sizeof(char));
	pstr[0] = (unsigned char) len;
	memcpy(&pstr[1], cstr, len);
	return pstr; 
}
