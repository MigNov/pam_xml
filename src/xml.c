#define DEBUG_XML

#define ROOT_ELEMENT "pam-definition"

#include "xml.h"

#ifdef DEBUG_XML
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "[pam_xml/main    ] " fmt , ## __VA_ARGS__); } while (0)
#ifdef DEBUG_ITERATE
#define DPRINTF_ITERATE(fmt, ...) \
do { fprintf(stderr, "[pam_xml/iterate ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF_ITERATE(fmt, ...) \
do {} while(0)
#endif
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#define DPRINTF_ITERATE(fmt, ...) \
do {} while(0)
#endif

int getIntValue(char *str)
{
	char *endptr = NULL;
	int tmp;

	errno = 0;
	tmp = strtol(str, &endptr, 10);
	if (errno != 0)
		return -1;
	return tmp;
}

int isEmptyString(char *val)
{
	int i;
	int ret = 1;

	for (i = 0; i < strlen(val); i++) {
		if ((val[i] == '\n') || (val[i] == 9))
			continue;
		if (val[i] != ' ')
			ret = 0;
	}

	return ret;
}

xmlNodeSetPtr xml_getNodeSet(xmlDocPtr doc, char *path)
{
	char tmp[8192] = { 0 };
	xmlXPathContextPtr context;
	xmlXPathObjectPtr op;

	context = xmlXPathNewContext(doc);
	if (context == NULL) {
		DPRINTF("%s: Cannot open document context (doc = %p)\n",
			__FUNCTION__, doc);
		return NULL;
	}

	if (path == NULL)
		snprintf(tmp, sizeof(tmp), "//%s", ROOT_ELEMENT);
	else {
		if (strncmp(path + 2, ROOT_ELEMENT, strlen(ROOT_ELEMENT)) == 0) {
			memset(tmp, 0, sizeof(tmp));
			strncpy(tmp, path, sizeof(tmp));
		}
		else
			snprintf(tmp, sizeof(tmp), "//%s/%s", ROOT_ELEMENT, path);
	}

	DPRINTF("%s: Opening node '%s'\n", __FUNCTION__, tmp);
	op = xmlXPathEvalExpression( (xmlChar *)tmp, context);
	xmlXPathFreeContext(context);
	if (op == NULL) {
		DPRINTF("%s: Cannot open node '%s'\n", __FUNCTION__,
			tmp);
		return NULL;
	}

	if(xmlXPathNodeSetIsEmpty(op->nodesetval)) {
		DPRINTF("%s: Node '%s' is empty\n", __FUNCTION__,
			tmp);
		xmlXPathFreeObject(op);
		return NULL;
	}

	DPRINTF("%s: Found %d key(s) in node '%s' \n",
		__FUNCTION__, op->nodesetval->nodeNr, tmp);

	strncpy(gRealPath[ndoch], tmp, sizeof(gRealPath[ndoch]));
	return op->nodesetval;
}

int xml_getResultCount(xmlDocPtr doc, char *path, char *attr)
{
	int ret = -1;
	xmlNodeSetPtr nodeset = xml_getNodeSet(doc, path);

	if (nodeset == NULL) {
		DPRINTF("%s: Nodeset returned empty result\n",
			__FUNCTION__);
		return ret;
	}

	return nodeset->nodeNr;
}

char *xml_getResultData(xmlDocPtr doc, char *path, char *attr, int pos)
{
	int num;
	xmlNodeSetPtr nodeset = xml_getNodeSet(doc, path);

	if (nodeset == NULL) {
		DPRINTF("%s: Nodeset returned empty result\n",
			__FUNCTION__);
		return NULL;
	}

	num = nodeset->nodeNr;
	if (pos > num) {
		DPRINTF("%s: Requested position (%d) exceeds maximum number of entries (%d)\n",
			__FUNCTION__, pos, num);
		return NULL;
	}

	if (attr == NULL) {
		DPRINTF("%s: Getting contents value from position #%d\n",
			__FUNCTION__, pos);

		return (char *)xmlNodeListGetString(doc, nodeset->nodeTab[pos]->xmlChildrenNode, 1);
	}

	DPRINTF("%s: Getting attribute '%s' value from position #%d\n",
		__FUNCTION__, attr, pos);

	return (char *)xmlGetProp(nodeset->nodeTab[pos], (xmlChar *)attr);
}

int xml_getAttributeCount(xmlNodePtr node)
{
	int nAttr = 0;
	xmlAttrPtr attr = NULL;

	for (attr = node->properties; NULL != attr; attr = attr->next)
		nAttr++;

	return nAttr;
}

tXmlAttrInfo xml_getAttributeList(xmlNodePtr node)
{
	int num = 0;
	char *val = NULL;
	xmlAttrPtr attr = NULL;
	tXmlAttrInfo attrinfo;

	attrinfo.nEntries = xml_getAttributeCount(node);

	attrinfo.attrs = (tAttributes *)malloc( attrinfo.nEntries * sizeof(tAttributes) );
	for (attr = node->properties; NULL != attr; attr = attr->next) {
		val = (char *)xmlGetProp(node, (xmlChar *)attr->name);
		attrinfo.attrs[num].name  = strdup((char *)attr->name);
		attrinfo.attrs[num].value = strdup((char *)val);
		xmlFree(val);
		num++;
	}

	return attrinfo;
}

void xml_FreeNodeInfo(tXmlNodeInfo info)
{
	int i;

	free(info.path);
	free(info.name);

	for (i = 0; i < info.attr.nEntries; i++) {
		free(info.attr.attrs[i].name);
		free(info.attr.attrs[i].value);
	}
}

int xml_getResultIterate(xmlDocPtr doc, char *path, tIterateFunc func)
{
	int ret = 0;
	xmlNodePtr cur = NULL;
	xmlNodeSetPtr nodeset = xml_getNodeSet(doc, path);

	if (nodeset == NULL) {
		DPRINTF("%s: Nodeset returned empty result\n",
			__FUNCTION__);
		return 0;
	}

	cur = nodeset->nodeTab[0];

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if (func != NULL) {
			tXmlNodeInfo xninfo;
			tXmlAttrInfo attrinfo = xml_getAttributeList(cur);

			xninfo.path = strdup(gRealPath[ndoch]);
			xninfo.name = strdup((char *)cur->name);
			xninfo.attr = attrinfo;

			if (func(xninfo, doc, cur->xmlChildrenNode) == 0)
				ret++;

			xml_FreeNodeInfo(xninfo);
		}

		DPRINTF_ITERATE("%s: Found element '%s' with value '%s' (on path '%s'; ndoch = %d)\n",
			__FUNCTION__, (char *)cur->name,
			(char *)xmlNodeListGetString(doc, cur->xmlChildrenNode, 1), gRealPath[ndoch], ndoch);

		cur = cur->next;
	}

	return ret;
}

uint32_t scriptGetVersion(xmlDocPtr doc, int *major, int *minor, int *micro)
{
	uint32_t res = 0;
	char *tmp = xml_getResultData(doc, NULL, "version", 0);

	if (major != NULL)
		*major = 0;
	if (minor != NULL)
		*minor = 0;
	if (micro != NULL)
		*micro = 0;

	if (tmp == NULL)
		return 0;

	char *str = NULL, *saveptr = NULL, *token = NULL;
	int tnum = 0, tval = -1;
	for (str = tmp; ; str = NULL) {
		token = strtok_r(str, ".", &saveptr);
		if (token == NULL)
			break;

		tval = getIntValue(token);
		if ((tnum > sizeof(res)) || (tval == -1)) {
			free(tmp);
			return 0;
		}

		if ((tnum == 0) && (major))
			*major = tval;
		if ((tnum == 1) && (minor))
			*minor = tval;
		if ((tnum == 2) && (micro))
			*micro = tval;

		res += tval << (tnum * 8);
		tnum++;
	}
	free(tmp);

	return res;
}

int scriptCheckVersion(uint32_t ver, int major, int minor, int micro)
{
	int vermajor, verminor, vermicro;

	vermajor = ver & 0xff;
	verminor = (ver >> 8) & 0xff;
	vermicro = (ver >> 16) & 0xff;

	return ((vermajor > major) || \
		((verminor == major) && (verminor > minor)) || \
		((vermajor == major) && (verminor == minor) && \
		(vermicro >= micro)));
}

char *getAttribute(tXmlAttrInfo attr, char *name)
{
	int i;

	if (attr.nEntries == 0)
		return NULL;

	for (i = 0; i < attr.nEntries; i++) {
		if (strcmp(attr.attrs[i].name, name) == 0)
			return attr.attrs[i].value;
	}

	return NULL;
}

tTokenizer tokenize(char *string, char *by)
{
	char *tmp;
	char *str;
	char *save;
	char *token;
	int i = 0;
	tTokenizer t;

	if (string == NULL) {
		t.numTokens = 0;
		return t;
	}

	tmp = strdup(string);
	t.tokens = (char **)malloc( sizeof(char *) );
	for (str = tmp; ; str = NULL) {
		token = strtok_r(str, by, &save);
		if (token == NULL)
			break;

		t.tokens = (char **)realloc( t.tokens, (i + 1) * sizeof(char *) );
		if (t.tokens == NULL)
			return t;
		t.tokens[i++] = strdup(token);
	}

	t.numTokens = i;
	return t;
}

void tokensFree(tTokenizer t)
{
	int i;

	for (i = 0; i < t.numTokens; i++)
		free(t.tokens[i]);
}

char *getPathToken(char *path, int index)
{
	char *ret = NULL;
	tTokenizer t;

	t.numTokens = 0;
	if (path == NULL)
		goto end;

	t = tokenize(path, "/");

	if ((index < 0) || (index > t.numTokens - 1))
		goto end;

	ret = strdup(t.tokens[index]);
end:
	tokensFree(t);

	return ret;
}

/* Variable handling functions */
int varChange(char *name, char *value)
{
	int i, ret = -ENOENT;

	for (i = 0; i < nVariables; i++) {
		if (strcmp(sVariables[i].name, name) == 0) {
			free(sVariables[i].value);
			sVariables[i].value = strdup(value);
			ret = 0;

			DPRINTF("%s: Variable '%s' changed to value '%s'\n",
				__FUNCTION__, name, value);
		}
	}

	return ret;
}

int varAdd(char *name, char *value)
{
	int idx = -1;
	if ((name == NULL) || (value == NULL))
		return -EINVAL;

	idx = varFind(name);

	if (idx > -1)
		return varChange(name, value);

	if (sVariables == NULL)
		sVariables = (tAttributes *)malloc( (nVariables + 1) * sizeof(tAttributes) );
	else
		sVariables = (tAttributes *)realloc( sVariables, (nVariables + 1) * sizeof(tAttributes) );

	if (sVariables == NULL)
		return -ENOMEM;

	sVariables[nVariables].name  = strdup(name);
	sVariables[nVariables].value = strdup(value);
	nVariables++;

	DPRINTF("%s: Added variable '%s' with value '%s' (variable count is %d)\n",
		__FUNCTION__, name, value, nVariables);
	return 0;
}

int varFind(char *name)
{
	int i;

	if (sVariables == NULL)
		return -1;

	if (name == NULL)
		return -1;

	for (i = 0; i < nVariables; i++)
		if (strcmp(sVariables[i].name, name) == 0)
			return i;

	return -1;
}

void varDump(void)
{
	int i;

	if (nVariables == 0)
		return;

	printf("Variable dump\n\n");
	for (i = 0; i < nVariables; i++) {
		printf("\tVariable #%d:\n", i + 1);
		printf("\t\tName:  %s\n", sVariables[i].name);
		printf("\t\tValue: %s\n\n", sVariables[i].value);
	}
}

void varFree(void)
{
	int i;

	for (i = 0; i < nVariables; i++) {
		free(sVariables[i].name);
		free(sVariables[i].value);
	}

	nVariables = 0;
}

int varDel(char *name)
{
	char *tmp1, *tmp2;
	int idx = varFind(name);

	if (idx < 0)
		return -ENOENT;

	if (nVariables - 1 == idx)
		goto end;

	tmp1 = strdup(sVariables[nVariables - 1].name);
	tmp2 = strdup(sVariables[nVariables - 1].value);

	free(sVariables[idx].name);
	free(sVariables[idx].value);

	sVariables[idx].name = tmp1;
	sVariables[idx].value = tmp2;

end:
	free(sVariables[nVariables - 1].name);
	free(sVariables[nVariables - 1].value);
	nVariables--;

	return 0;
}

char *varGet(char *name)
{
	int idx = varFind(name);

	if (idx < 0)
		return NULL;

	return sVariables[idx].value;
}

int processXml_OLD(char *xmlFile) {
	xmlDocPtr doc = NULL;
	int rc = 1;

	memset(gRealPath[ndoch], 0, sizeof(gRealPath[ndoch]));

	if (access(xmlFile, R_OK) != 0) {
//		fprintf(stderr, "Error: File '%s' doesn't exist or is not accessible for reading.\n", xmlFile);
		rc = -EPERM;
		goto end;
	}

	DPRINTF("%s: File '%s' accessible ...\n", __FUNCTION__, xmlFile);

	doc = xmlParseFile(xmlFile);
	if (doc == NULL) {
//		fprintf(stderr, "Error: Cannot parse file '%s'\n", xmlFile);
		rc = -EINVAL;
		goto end;
	}

	DPRINTF("%s: Version checking file '%s'\n", __FUNCTION__, xmlFile);

	if (!scriptCheckVersion(
		scriptGetVersion(doc, NULL, NULL, NULL), 0, 0, 1)) {
//			fprintf(stderr, "Error: Invalid script version\n");
			rc = -EINVAL;
			goto end;
		}

	DPRINTF("%s: File '%s' passed version check\n", __FUNCTION__, xmlFile);

/*
	int cnt = xml_getResultCount(doc, NULL, "version");
	char *tmp = xml_getResultData(doc, "something", "attr", 0);
	if (tmp != NULL)
		printf("DATA: '%s'\n", tmp);
	free(tmp);

	tmp = xml_getResultData(doc, "something-else", NULL, 0);
	if (tmp != NULL)
		printf("DATA2: '%s'\n", tmp);
	free(tmp);
*/

	int cnt = xml_getResultCount(doc, NULL, NULL);
	printf("Result count: %d\n", cnt);

	memset(gRealFileName, 0, sizeof(gRealFileName));
	strncpy(gRealFileName, xmlFile, sizeof(gRealFileName));

	ndoch = 0;
	xml_getResultIterate(doc, NULL, xml_CDL_Iterator);

	rc = 0;
end:
	DPRINTF("%s: Closing document objects\n", __FUNCTION__);

	xmlFreeDoc(doc);
	xmlCleanupParser();

	DPRINTF("%s: All done. Returning value %d.\n",
		__FUNCTION__, rc);

	return rc;
}

int processXml(char *xmlFile) {
	xmlDocPtr doc = NULL;
	int rc = 1;

	sXmlNodeInfo = NULL;
	nXmlNodeInfo = 0;

	sVariables = NULL;
	nVariables = 0;

	memset(gRealPath[0], 0, sizeof(gRealPath[0]));

	if (access(xmlFile, R_OK) != 0) {
		rc = -EPERM;
		goto end;
	}

	DPRINTF("%s: File '%s' accessible ...\n", __FUNCTION__, xmlFile);

	doc = xmlParseFile(xmlFile);
	if (doc == NULL) {
		rc = -EINVAL;
		goto end;
	}

	DPRINTF("%s: Version checking file '%s'\n", __FUNCTION__, xmlFile);

	if (!scriptCheckVersion(
		scriptGetVersion(doc, NULL, NULL, NULL), 0, 0, 1)) {
			rc = -EINVAL;
			goto end;
		}

	DPRINTF("%s: File '%s' passed version check\n", __FUNCTION__, xmlFile);

	memset(gRealFileName, 0, sizeof(gRealFileName));
	strncpy(gRealFileName, xmlFile, sizeof(gRealFileName));
	xml_getResultIterate(doc, NULL, xml_CDL_Iterator);

	rc = 0;
end:
	DPRINTF("%s: Closing document objects\n", __FUNCTION__);

	xmlFreeDoc(doc);
	xmlCleanupParser();

	varDump();

	varFree();

	DPRINTF("%s: All done. Returning value %d.\n",
		__FUNCTION__, rc);

	return rc;
}

