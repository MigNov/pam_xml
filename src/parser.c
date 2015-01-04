#define DEBUG_PARSER

#include "xml.h"

#ifdef DEBUG_PARSER
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "[pam_xml/parser  ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

float handle_convert(tXmlAttrInfo attr, char *val)
{
	float ret = INVALID_VALUE_FLOAT;
	char *tmp = getAttribute(attr, "type");

	if (tmp == NULL)
		return ret;

	if (ret != INVALID_VALUE_FLOAT) {
		char sr[16] = { 0 };

		snprintf(sr, sizeof(sr), "%.6f", ret);
		varAdd(val, sr);

		ret = 0;
	}
	else
		ret = -EINVAL;

	return ret;
}

int cmdIsCondition(char *type)
{
	return (strncmp(type, "if", 2) == 0) ? 1 : 0;
}

int conditionValid(char *type, char *val)
{
	int ret = 0;
	float v1, v2;

	v1 = INVALID_VALUE_FLOAT;
	v2 = INVALID_VALUE_FLOAT;

	if ((type == NULL) || (val == NULL))
		return ret;

	tTokenizer t = tokenize(val, ",");
	if (t.numTokens != 2)
		goto end;

	v1 = atof(t.tokens[0]);
	v2 = atof(t.tokens[1]);

	if (strcmp(type, "eq") == 0) {
		DPRINTF("%s: Testing whether v1 (%.6f) and v2 (%.6f) equals\n",
			__FUNCTION__, v1, v2);

		ret = ((v1 == v2) ? 1 : 0);
	}
	else
	if (strcmp(type, "ne") == 0) {
		DPRINTF("%s: Testing whether v1 (%.6f') does not equal v2 (%.6f)\n",
			__FUNCTION__, v1, v2);

		ret = ((v1 != v2) ? 1 : 0);
	}
	else
	if (strcmp(type, "le") == 0) {
		DPRINTF("%s: Testing whether v1 (%.6f) is less or equal v2 (%.6f)\n",
			__FUNCTION__, v1, v2);

		ret = ((v1 <= v2) ? 1 : 0);
	}
	else
	if (strcmp(type, "lt") == 0) {
		DPRINTF("%s: Testing whether v1 (%.6f) is less than v2 (%.6f)\n",
			__FUNCTION__, v1, v2);

		ret = ((v1 < v2) ? 1 : 0);
	}
	else
	if (strcmp(type, "ge") == 0) {
		DPRINTF("%s: Testing whether v1 (%.6f) is greater or equal v2 (%.6f)\n",
			__FUNCTION__, v1, v2);

		ret = ((v1 >= v2) ? 1 : 0);
	}
	else
	if (strcmp(type, "gt") == 0) {
		DPRINTF("%s: Testing whether v1 (%.6f) is greater than v2 (%.6f)\n",
			__FUNCTION__, v1, v2);

		ret = ((v1 > v2) ? 1 : 0);
	}
end:
	tokensFree(t);

	DPRINTF("%s('%s', '%s') returning %d (%s)\n",
		__FUNCTION__, type, val, ret,
		(ret == 1) ? "true" : "false");
	return ret;
}

void _dumpAttributes(tXmlAttrInfo attr, char *prefix)
{
	if (attr.nEntries > 0) {
		int i;

		DPRINTF("%sAttributes (%d)\n", prefix, attr.nEntries);
		for (i = 0; i < attr.nEntries; i++) {
			DPRINTF("\t%sAttribute '%s': '%s'\n",
				prefix,
				attr.attrs[i].name,
				attr.attrs[i].value);
		}
}
}

/* Custom functions */
int xml_CDL_Iterator(tXmlNodeInfo info, xmlDocPtr doc, xmlNodePtr node)
{
	int ret = 0;
	char *val = (char *)xmlNodeListGetString(doc, node, 1);

	if ((strcmp(info.name, "text") == 0) && (val == NULL))
		return 0;

	if (val == NULL) {
		DPRINTF("xml_Iterator('%s'): '%s' => NULL value\n", info.path, info.name);

		_dumpAttributes(info.attr, "");
	}
	else
	if (isEmptyString(val)) {
		char tmp[8192] = { 0 };
		int canProceed = 1;

		DPRINTF("xml_Iterator('%s'): '%s' => <command-block>\n", info.path, info.name);
		_dumpAttributes(info.attr, "Block ");

		snprintf(tmp, sizeof(tmp), "%s/%s", info.path, info.name);

		if (cmdIsCondition(info.name)) {
			int isValid = 0;
			// First condition type is simple 'if' condition
			if (strcmp(info.name, "if") == 0) {
				if (conditionValid( getAttribute(info.attr, "type"), getAttribute(info.attr, "val") ) == 1)
					isValid = 1;
			}

			// Second condition type
			if (strcmp(info.name, "ifWithOperand") == 0) {
				int v1 = conditionValid( getAttribute(info.attr, "type1"), getAttribute(info.attr, "val1") );
				int v2 = conditionValid( getAttribute(info.attr, "type2"), getAttribute(info.attr, "val2") );\
				char *tmp = getAttribute(info.attr, "operand");

				if (tmp != NULL) {
					if (strcmp(tmp, "and") == 0) {
						isValid = (v1 && v2) ? 1 : 0;
					}
					else
					if (strcmp(tmp, "or") == 0) {
						isValid = (v1 || v2) ? 1 : 0;
					}
					else
					if (strcmp(tmp, "xor") == 0) {
						isValid = ((!v1 && v2) || (v1 && !v2)) ? 1 : 0;
					}
					else
					if (strcmp(tmp, "nand") == 0) {
						isValid = (v1 && v2) ? 0 : 1;
					}
					else
					if (strcmp(tmp, "nor") == 0) {
						isValid = (v1 || v2) ? 0 : 1;
					}
					else
					if (strcmp(tmp, "nxor") == 0) {
						isValid = ((!v1 && v2) || (v1 && !v2)) ? 0 : 1;
					}
					else {
						ret = -EINVAL;
						goto end;
					}
				}
				DPRINTF("ifWithOperand(('%s', '%s') %s ('%s', '%s')): isValid = %d\n",
					getAttribute(info.attr, "type1"), getAttribute(info.attr, "val1"), tmp,
					getAttribute(info.attr, "type2"), getAttribute(info.attr, "val2"), isValid);
			}

			if (!isValid)
				canProceed = 0;
		}

		if (canProceed) {
			int idx = ndoch++;
			doch[idx] = xmlParseFile(gRealFileName);
			xml_getResultIterate(doch[idx], tmp, xml_CDL_Iterator);
			xmlFreeDoc(doch[idx]);
			ndoch--;
		}
		else
			DPRINTF("%s: Skipping as condition is not met\n", __FUNCTION__);

		goto end_block;
	}
	else {
		DPRINTF("xml_Iterator('%s'): '%s' => '%s'\n", info.path, info.name, val);
		_dumpAttributes(info.attr, "");

		char *tmp = getPathToken(info.path, 1);
		if ((tmp != NULL) && (strcmp(tmp, "code") == 0)) {
			ret = -ENOTSUP;
			if (strcmp(info.name, "convert") == 0)
				ret = handle_convert(info.attr, val);
		}
		free(tmp);
	}

	goto end;
end_block:
	DPRINTF("%s(path = '%s', block = '%s'): Returning value %d\n",
		__FUNCTION__, info.path, info.name, ret);
	goto real_end;
end:
	DPRINTF("%s(path = '%s', name = '%s'): Returning value %d\n",
		__FUNCTION__, info.path, info.name, ret);
real_end:
	return 0;
}

