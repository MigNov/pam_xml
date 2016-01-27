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

#define	VERSION				"0.0.1"
#define	CURL_USER_AGENT_PAM		"PAM-XML Authentication Service/" VERSION
#define	CURL_SKIP_PEER_VERIFICATION	0x01

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
#include <stdarg.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <security/pam_ext.h>

#include <curl/curl.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

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

#define	INS_READ		0x01
#define	INS_DATABASE		0x02

pam_handle_t *gPamh;

char gRealPath[MAX_LEVELS][8192];
char gRealFileName[8192];
xmlDocPtr doch[MAX_LEVELS];
int ndoch;

char *gFn;
char *gRuleset;
char *gPlainPassword;
char *gAlgo;
char *gLogFile;
char *gUser;
char *gPassword;
int gRulesetAdd;
int gIsValid;
int gDocPAMOK;
int gDocPAMErr;
int shouldReturn;

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

typedef struct tInstruction {
	int type;
	char *attr1;
	char *attr2;
	char *attr3;
} tInstruction;

typedef struct tVariable {
	int type;
	char *name;
	char *sValue;
	int iValue;
} tVariable;

// No need to have it dynamic yet
#define MAX_VARS	0xFF

#define	VAR_STR		0x01
#define	VAR_INT		0x02

tVariable gVars[MAX_VARS];
int nVars;

tInstruction instruction;

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

int translate_pam_code(char *code);
int scriptGetDefaultReturnValue(xmlDocPtr doc, int typeError);
void instructionPush(int type, char *attr1, char *attr2, char *attr3);
char *instructionPop(int type, int id);
char *replace(char *str, char *what, char *with);
char *replaceAll(char *str, char *what, char *with);
char *runGenerator(char *type, int size);
char *curlRequest(char *url, char *data, int flags);
char *getConversation(char *prompt, int echo);

int algGetType(const char *name);
int isAlgoSupported(const char *name);
char *hashMD5(char *string);
char *hashSHA1(char *string);
char *hashSHA256(char *string);

void _log(int inc, const char *format, ...);
char *databaseSelect(char *type, char *connstr, char *query);

/* Implementation stuff */
//int xml_CDL_Iterator(char *path, char *name, xmlDocPtr doc, xmlNodePtr node);
int xml_CDL_Iterator(tXmlNodeInfo info, xmlDocPtr doc, xmlNodePtr node);
#endif
