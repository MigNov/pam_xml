#define DEBUG_XML
//#define DEBUG_ITERATE

#define ROOT_ELEMENT "pam-definition"

#include "xml.h"

#ifdef DEBUG_XML
#define DPRINTF(fmt, ...) \
do { _log( 0, "[pam_xml/xml     ] " fmt , ## __VA_ARGS__); } while (0)
#ifdef DEBUG_ITERATE
#define DPRINTF_ITERATE(fmt, ...) \
do { _log( 0, "[pam_xml/xml-iter] " fmt , ## __VA_ARGS__); } while (0)
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

char *curlRequest(char *url, char *data, int flags)
{
        CURL *curl;
        CURLcode res;
        long http_code = 0;

	DPRINTF("%s: Requesting URL '%s' ...\n", __FUNCTION__, url);

        curl_global_init(CURL_GLOBAL_DEFAULT);

        char *fn = tempnam("/tmp", "tmppaxXXXXXX");
        FILE *fp = fopen(fn, "w");

        curl = curl_easy_init();
        if(curl) {
                curl_easy_setopt(curl, CURLOPT_URL, url);

                if ((flags & CURL_SKIP_PEER_VERIFICATION) == 0)
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

                if ((flags & CURL_SKIP_PEER_VERIFICATION) == 0)
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

                curl_easy_setopt(curl, CURLOPT_USERAGENT, CURL_USER_AGENT_PAM);

		if (data != NULL)
	                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

                curl_easy_setopt(curl, CURLOPT_WRITEDATA,  (void *)fp);

                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                        //fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
                        free(fn);
                        fn = NULL;
                }
                else
                        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                curl_easy_cleanup(curl);
        }
        else {
                free(fn);
                fn = NULL;
        }

        curl_global_cleanup();
        fclose(fp);

        return fn;
}

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

	op = xmlXPathEvalExpression( (xmlChar *)"//"ROOT_ELEMENT, context);
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
	/*
	if (path != NULL) {
		DPRINTF("%s: Node count is %d\n", __FUNCTION__, nodeset->nodeNr);
		if (nodeset->nodeNr > 1) {
			DPRINTF("%s: Trying another node\n", __FUNCTION__);
			cur = nodeset->nodeTab[1];
		}
	}
	*/

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

	//DPRINTF("%s: Returning value %d\n", __FUNCTION__, ret);
	return ret;
}

char *runGenerator(char *type, int size)
{
	char *out;

	char *aNumeric = "0123456789";
	char *aHexaDecimal = "0123456789ABCDEF";
	char *aAlphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char *aAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	// numeric, alphanumeric, hexadecimal, alpha
	//
	if ((strcmp(type, "numeric") != 0) && (strcmp(type, "alphanumeric") != 0)
		&& (strcmp(type, "hexadecimal") != 0) && (strcmp(type, "alpha") != 0))
		return NULL;

	srand(time(NULL));

	out = malloc( (size + 1) * sizeof(char) );
	memset(out, 0, (size + 1) * sizeof(char));

	int i, r;
	char a[2] = { 0 };
	for (i = 0; i < size; i++) {
		r = rand();

		if (strcmp(type, "numeric") == 0)
			a[0] = aNumeric[r % strlen(aNumeric)];
		if (strcmp(type, "alphanumeric") == 0)
			a[0] = aAlphaNum[r % strlen(aAlphaNum)];
		if (strcmp(type, "hexadecimal") == 0)
			a[0] = aHexaDecimal[r % strlen(aHexaDecimal)];
		if (strcmp(type, "alpha") == 0)
			a[0] = aAlpha[r % strlen(aAlpha)];

		strcat(out, a);
	}

	DPRINTF("%s('%s', %d) returned '%s'\n", __FUNCTION__, type, size, out);
	return out;
}

char *replace(char *str, char *what, char *with)
{
	int size, idx;
	char *new, *part, *old;

	part = strstr(str, what);
	if (part == NULL)
		return str;

	size = strlen(str) - strlen(what) + strlen(with);
	new = (char *)malloc( (size + 1) * sizeof(char) );
	old = strdup(str);
	idx = strlen(str) - strlen(part);
	old[idx] = 0;
	strcpy(new, old);
	strcat(new, with);
	strcat(new, part + strlen(what) );
	part = NULL;
	old = NULL;
	return new;
}

char *replaceAll(char *str, char *what, char *with)
{
	char *t = NULL;
	char *s = NULL;

	s = str;
	while (strstr(s, what) != NULL) {
		t = replace(s, what, with);
		s = t;
	}

	return s;
}

void instructionPush(int type, char *attr1, char *attr2, char *attr3)
{
	DPRINTF("%s: Pushing instruction 0x%02x\n", __FUNCTION__, type);

	if (instruction.attr1 != NULL)
		free(instruction.attr1);
	if (instruction.attr2 != NULL) 
		free(instruction.attr2);
	if (instruction.attr3 != NULL)
		free(instruction.attr3);

	instruction.type = type;
	instruction.attr1 = (attr1 != NULL) ? strdup(attr1) : NULL;
	instruction.attr2 = (attr2 != NULL) ? strdup(attr2) : NULL;
	instruction.attr3 = (attr3 != NULL) ? strdup(attr3) : NULL;
}

char *instructionPop(int type, int id)
{
	if (instruction.type != type)
		return NULL;

	if (id == 0)
		return instruction.attr1;
	else
	if (id == 1)
		return instruction.attr2;
	else
	if (id == 2)
		return instruction.attr3;

	return NULL;
}

int scriptGetDefaultReturnValue(xmlDocPtr doc, int typeError)
{
	int ret = -1;
	char *tmp = NULL;

	tmp = xml_getResultData(doc, NULL, typeError ? "error" : "success", 0);
	ret = translate_pam_code(tmp);
	free(tmp);

	DPRINTF("%s(error = %d) returned %d\n", __FUNCTION__, typeError, ret);

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

	//DPRINTF("%s: All done. Returning value %d.\n",
	//	__FUNCTION__, rc);

	return rc;
}

int processXml(char *xmlFile) {
	xmlDocPtr doc = NULL;
	int rc = 1;

	if ((gUser == NULL) || (gPassword == NULL)) {
		fprintf(stderr, "Error: Invalid call (not within PAM module).\n");
		return -EINVAL;
	}

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

	int iTmp;
	iTmp = scriptGetDefaultReturnValue(doc, 0);
	if (iTmp != -1)
		gDocPAMOK = iTmp;
	iTmp = scriptGetDefaultReturnValue(doc, 1);
	if (iTmp != -1)
		gDocPAMErr = iTmp;

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

	//DPRINTF("%s: All done. Returning value %d.\n",
	//	__FUNCTION__, rc);

	return rc;
}

