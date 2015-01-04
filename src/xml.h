/* Uncomment to enable debugging messages from all source files */
#define DEBUG_ALL
#define DEBUG_NO_ITERATOR

#ifndef XML_H
#define XML_H
#define _XOPEN_SOURCE 600

#define	MAX_LEVELS	8

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#ifdef DEBUG_ALL
#define DEBUG
#define DEBUG_XML
#ifndef DEBUG_NO_ITERATOR
#define DEBUG_ITERATE
#endif
#endif

#define INVALID_VALUE_FLOAT	-1000000

#define	PIN_MODE_INPUT		0x01
#define	PIN_MODE_OUTPUT		0x02
#define	PIN_MODE_CONTINUOUS	0x20

char gRealPath[MAX_LEVELS][8192];
char gRealFileName[8192];
xmlDocPtr doch[MAX_LEVELS];
int ndoch;

typedef struct tAttributes {
	char *name;
	char *value;
} tAttributes;

typedef struct tXmlAttrInfo {
	int nEntries;
	tAttributes *attrs;
} tXmlAttrInfo;

typedef struct tXmlNodeInfo {
	char *path;
	char *name;
	tXmlAttrInfo attr;
} tXmlNodeInfo;

typedef struct tTokenizer {
	char **tokens;
	int numTokens;
} tTokenizer;

tXmlNodeInfo *sXmlNodeInfo;
int           nXmlNodeInfo;

tAttributes  *sVariables;
int           nVariables;

//typedef int (tIterateFunc)(char *path, char *name, xmlDocPtr doc, xmlNodePtr node);
typedef int (tIterateFunc)(tXmlNodeInfo xninfo, xmlDocPtr doc, xmlNodePtr node);

/* Function prototypes */
/* XML stuff */
int processXml(char *xmlFile);

/* Misc stuff */
int getIntValue(char *str);
int isEmptyString(char *val);
int xml_getResultIterate(xmlDocPtr doc, char *path, tIterateFunc func);
xmlNodeSetPtr xml_getNodeSet(xmlDocPtr doc, char *path);
int xml_getResultCount(xmlDocPtr doc, char *path, char *attr);
char *xml_getResultData(xmlDocPtr doc, char *path, char *attr, int pos);
char *getAttribute(tXmlAttrInfo attr, char *name);
char *getPathToken(char *path, int index);
tTokenizer tokenize(char *string, char *by);
void tokensFree(tTokenizer t);
int varAdd(char *name, char *value);
int varFind(char *name);
int varDel(char *name);
char *varGet(char *name);
void varDump(void);
void varFree(void);

/* Implementation stuff */
//int xml_CDL_Iterator(char *path, char *name, xmlDocPtr doc, xmlNodePtr node);
int xml_CDL_Iterator(tXmlNodeInfo info, xmlDocPtr doc, xmlNodePtr node);
#endif
