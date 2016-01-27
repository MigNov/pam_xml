#define DEBUG_PARSER

#include "xml.h"

#ifdef DEBUG_PARSER
#define DPRINTF(fmt, ...) \
do { _log(0, "[pam_xml/parser  ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

int translate_pam_code(char *code)
{
	if (strcmp(code, "PAM_SUCCESS") == 0)
		return PAM_SUCCESS;
	if (strcmp(code, "PAM_PERM_DENIED") == 0)
		return PAM_PERM_DENIED;
	if (strcmp(code, "PAM_AUTH_ERR") == 0)
		return PAM_AUTH_ERR;
	if (strcmp(code, "PAM_AUTHINFO_UNAVAIL") == 0)
		return PAM_AUTHINFO_UNAVAIL;
	if (strcmp(code, "PAM_USER_UNKNOWN") == 0)
		return PAM_USER_UNKNOWN;
	if (strcmp(code, "PAM_MAXTRIES") == 0)
		return PAM_MAXTRIES;
	if (strcmp(code, "PAM_NEW_AUTHTOK_REQD") == 0)
		return PAM_NEW_AUTHTOK_REQD;
	if (strcmp(code, "PAM_ACCT_EXPIRED") == 0)
		return PAM_ACCT_EXPIRED;
	if (strcmp(code, "PAM_TRY_AGAIN") == 0)
		return PAM_TRY_AGAIN;
	if (strcmp(code, "PAM_IGNORE") == 0)
		return PAM_IGNORE;
	if (strcmp(code, "PAM_AUTHTOK_EXPIRED") == 0)
		return PAM_AUTHTOK_EXPIRED;

	return PAM_SERVICE_ERR;
}

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
	return (strncmp(type, "condition", 9) == 0) ? 1 : 0;
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

char *saveTempXml(xmlDocPtr doc, xmlNodePtr node)
{
	char line[1024] = { 0 };
	char *xre = NULL;
	int idx = 0;

	char fn1[] = "/tmp/pamxmlXXXXXX";
	char fn2[] = "/tmp/pamxmqXXXXXX";

	close(mkstemp(fn1));
	close(mkstemp(fn2));

	FILE *fp = fopen(fn1, "w");
	xmlElemDump(fp, doc, node);
	fclose(fp);

	FILE *fp2 = fopen(fn2, "w");
	fprintf(fp2, "<pam-definition>\n");

	int lc = 0;
	fp = fopen(fn1, "r");
	memset(line, 0, sizeof(line));
	while (!feof(fp)) {
		fgets(line, sizeof(line), fp);
		lc++;
	}
	fclose(fp);

	memset(line, 0, sizeof(line));
	fp = fopen(fn1, "r");
	while (!feof(fp)) {
		fgets(line, sizeof(line), fp);

		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = 0;

		if (strlen(line) > 0) {
			if ((idx == 0) || (idx == lc - 1)) {
				tTokenizer xt = tokenize(line, " ");
				xre = strdup(xt.tokens[0] + 1);
				tokensFree(xt);
			}
			else
				fprintf(fp2, "%s\n", line);
		}

		idx++;
		memset(line, 0, sizeof(line));
	}
	fprintf(fp2, "</pam-definition>\n");
	fclose(fp2);
	fclose(fp);
	free(xre);

	unlink(fn1);
	return strdup(fn2);
}

int variableGetIdx(char *name)
{
	int i;

	for (i = 0; i < nVars; i++) {
		if (strcmp(gVars[i].name, name) == 0)
			return i;
	}

	return -1;
}

void variableSave(char *name, char *value, int iVal, int type)
{
	int idx = variableGetIdx(name);
	if (idx >= 0) {
		DPRINTF("%s: Updating variable '%s' with value '%s' (<int>%d)...\n",
			 __FUNCTION__, name, value, iVal);

		gVars[idx].type = type;
		gVars[idx].sValue = (value != NULL) ? strdup(value) : NULL;
		gVars[idx].iValue = iVal;

		return;
	}

	DPRINTF("%s: Saving variable '%s' with value '%s' (<int>%d)...\n",
		__FUNCTION__, name, value, iVal);

	gVars[nVars].type = type;
	gVars[nVars].name = strdup(name);
	gVars[nVars].sValue = (value != NULL) ? strdup(value) : NULL;
	gVars[nVars].iValue = iVal;
	nVars++;
}

void variableDump(void)
{
	int i;

	for (i = 0; i < nVars; i++) {
		DPRINTF("Variable #%d:\n", i);
		DPRINTF("\tType: %d\n", gVars[i].type);
		DPRINTF("\tName: %s\n", gVars[i].name);
		DPRINTF("\tValS: %s\n", gVars[i].sValue);
		DPRINTF("\tValI: %d\n", gVars[i].iValue);
	}
}

/* Custom functions */
int xml_CDL_Iterator(tXmlNodeInfo info, xmlDocPtr doc, xmlNodePtr node)
{
	int ret = 0;
	char *val = (char *)xmlNodeListGetString(doc, node, 1);

	if (shouldReturn)
		return 0;

	if ((strcmp(info.name, "text") == 0) && (val == NULL))
		return 0;

	if (val == NULL) {
		//DPRINTF("xml_Iterator('%s'): '%s' => NULL value\n", info.path, info.name);

		_dumpAttributes(info.attr, "");
	}
	else
	if (isEmptyString(val)) {
		char tmp[8192] = { 0 };
		int canProceed = 1;

		DPRINTF("xml_Iterator('%s'): '%s' => <command-block>\n", info.path, info.name);
		_dumpAttributes(info.attr, "Block ");

		snprintf(tmp, sizeof(tmp), "%s/%s", info.path, info.name);

		if ((strcmp(info.path, "//pam-definition") == 0) && (strcmp(info.name, "authentication") == 0)) {
			if (getAttribute(info.attr, "default") != NULL) {
				gIsValid = translate_pam_code(getAttribute(info.attr, "default"));
				if (gIsValid == PAM_SERVICE_ERR) {
					if (strcmp(getAttribute(info.attr, "default"), "success") == 0)
						gIsValid = gDocPAMOK;
					else
					if (strcmp(getAttribute(info.attr, "default"), "error") == 0)
						gIsValid = gDocPAMErr;
				}
			}
		}

		if (strcmp(info.name, "read") == 0) {
			//DPRINTF("%s: Command block for read = { type: '%s', output: '%s' }\n",
			//	__FUNCTION__, getAttribute(info.attr, "type"),
			//	 getAttribute(info.attr, "output"));

			instructionPush(INS_READ, getAttribute(info.attr, "type"), getAttribute(info.attr, "output"), NULL);
		}
		else
		if (strcmp(info.name, "database") == 0) {
			char *oVal = NULL;
			DPRINTF("%s: Command block for database = { type: '%s', connstr: '%s' }\n",
				__FUNCTION__, getAttribute(info.attr, "type"), getAttribute(info.attr, "connstr"));

			if (getAttribute(info.attr, "password-preprocess") != NULL) {
				char *vl = strdup(getAttribute(info.attr, "password-preprocess"));

				oVal = replaceAll(vl, "%USERNAME%", gUser);
                                vl   = replaceAll(oVal, "%PASSWORD%", gPassword);
                                oVal = replaceAll(vl, "%PLAINPASSWORD%", gPlainPassword);

				if (getAttribute(info.attr, "alg") != NULL) {
					char *tmp = NULL;
					switch (algGetType(getAttribute(info.attr, "alg"))) {
						case 1: tmp = hashMD5(oVal);
							break;
						case 2: tmp = hashSHA1(oVal);
							break;
						case 3: tmp = hashSHA256(oVal);
							break;
					}
					free(oVal);
					oVal = tmp;
				}
			}

			instructionPush(INS_DATABASE, getAttribute(info.attr, "type"), getAttribute(info.attr, "connstr"), oVal);
		}
		else
		if (cmdIsCondition(info.name)) {
			int isValid = 0;

			if (getAttribute(info.attr, "user") != NULL)
				if (strcmp(getAttribute(info.attr, "user"), gUser) == 0)
					isValid = 1;

			if (getAttribute(info.attr, "type") != NULL) {
				if (strcmp(getAttribute(info.attr, "type"), "isNull") == 0) {
					int aV = variableGetIdx(getAttribute(info.attr, "arg1"));

					if (aV >= 0) {
						if (gVars[aV].sValue == NULL)
							isValid = 1;
					}
				}
				else
				if ((strcmp(getAttribute(info.attr, "type"), "ne") == 0) ||
					(strcmp(getAttribute(info.attr, "type"), "eq") == 0)) {
					char *arg1 = getAttribute(info.attr, "arg1");
					char *arg2 = getAttribute(info.attr, "arg2");

					int met = 0;

					if (strncmp(arg2, "contains:", 9) == 0) {
						arg2 = arg2 + 9;

						int aV = variableGetIdx(arg1);
						if (aV >= 0) {
							if (gVars[aV].sValue != NULL) {
								if (strstr(gVars[aV].sValue, arg2) != NULL)
									met = 1;
							}
						}
					}
					else
					if (strncmp(arg2, "string:", 7) == 0) {
						arg2 = arg2 + 7;

						int aV = variableGetIdx(arg1);
						if (aV >= 0) {
							if (gVars[aV].sValue != NULL) {
								if (strcmp(gVars[aV].sValue, arg2) == 0)
									met = 1;
							}
						}
					}
					else {
						int aV1 = variableGetIdx(arg1);
						int aV2 = variableGetIdx(arg2);

						if ((aV1 >= 0) && (aV2 >= 0)) {
							if ((gVars[aV1].sValue != NULL) && (gVars[aV2].sValue != NULL)) {
								if (strcmp(gVars[aV1].sValue, gVars[aV2].sValue) == 0)
									met = 1;
							}
						}
					}

					if ((strcmp(getAttribute(info.attr, "type"), "ne") == 0) && (met == 0))
						isValid = 1;
					else
					if ((strcmp(getAttribute(info.attr, "type"), "eq") == 0) && (met == 1))
						isValid = 1;
				}
			}

			if (!isValid)
				canProceed = 0;
		}

		if (canProceed) {
			char *fn = NULL;
			if ((node != NULL) && (node->parent != NULL))
				fn = saveTempXml(doc, node->parent);

			int idx = ndoch++;
			doch[idx] = xmlParseFile(fn);
			//DPRINTF("%s: Opening file '%s'\n", __FUNCTION__, fn);
			xml_getResultIterate(doch[idx], tmp, xml_CDL_Iterator);
			xmlFreeDoc(doch[idx]);
			//DPRINTF("%s: Closing file '%s'\n", __FUNCTION__, fn);
			ndoch--;
			unlink(fn);
		}
		//else
		//	DPRINTF("%s: Skipping as condition is not met\n", __FUNCTION__);

		goto end_block;
	}
	else {
		DPRINTF("xml_Iterator('%s'): '%s' => '%s'\n", info.path, info.name, val);
		_dumpAttributes(info.attr, "");

		if (strcmp(info.name, "variable") == 0) {
			char *type = getAttribute(info.attr, "type");
			char *name = getAttribute(info.attr, "name");

			if (strcmp(type, "set") == 0)
				variableSave(name, val, 0, VAR_STR);
			else
			if (strcmp(type, "del") == 0)
				DPRINTF("Variable '%s' should get deleted ...\n", name);
		}
		else
		if (strcmp(info.name, "convert") == 0) {
			char *type = getAttribute(info.attr, "type");
			char *input = getAttribute(info.attr, "input");

			int idx = variableGetIdx(input);
			if ((idx >= 0) && (strcmp(type, "numeric") == 0)) {
				if (gVars[idx].sValue != NULL) {
					variableSave(val, NULL, atoi(gVars[idx].sValue), VAR_INT);
				}
			}
		}
		else
		if (strcmp(info.name, "generator") == 0) {
			char *type = getAttribute(info.attr, "type");
			char *size = getAttribute(info.attr, "size");
			int iSize = 0;

			int sV = variableGetIdx(size);
			if (sV >= 0)
				iSize = gVars[sV].iValue;

			char *out = runGenerator(type, iSize);
			variableSave(val, out, 0, VAR_STR);
		}
		else
		if (strcmp(info.name, "select") == 0) {
			int inDatabase = 0;

			tTokenizer t = tokenize(info.path, "/");
			if (strcmp(t.tokens[t.numTokens - 1], "database") == 0)
				inDatabase = 1;
			tokensFree(t);

			char *var = strdup(val);
			if (inDatabase) {
				char *oVal;
				char *type = instructionPop(INS_DATABASE, 0);
				char *connstr = instructionPop(INS_DATABASE, 1);
				char *prepPassword = instructionPop(INS_DATABASE, 2);
				char *table = getAttribute(info.attr, "table");
				char *field = getAttribute(info.attr, "field");
				char *condition = getAttribute(info.attr, "condition");

				oVal = replaceAll(condition, "%USERNAME%", gUser);
				val  = replaceAll(oVal, "%PASSWORD%", gPassword);
				oVal = val;

				if (prepPassword != NULL)
					val  = replaceAll(oVal, "%PREPPASSWORD%", prepPassword);

				oVal = val;

				char tmp[4096] = { 0 };
				snprintf(tmp, sizeof(tmp), "SELECT %s FROM %s WHERE %s", field, table, oVal);

				variableSave(var, databaseSelect(type, connstr, tmp), 0, VAR_STR);
			}
		}
                else
		if (strcmp(info.name, "data") == 0) {
			int inRead = 0;

			tTokenizer t = tokenize(info.path, "/");
			if (strcmp(t.tokens[t.numTokens - 1], "read") == 0)
				inRead = 1;
			tokensFree(t);

			if (inRead) {
				char *oVal = NULL;
				char *type = instructionPop(INS_READ, 0);
				char *output = instructionPop(INS_READ, 1);

				if ((type != NULL) && (strncmp(type, "file", 4) == 0)) {
					if (access(val, R_OK) == 0) {
						FILE *fp = fopen(val, "r");
						if (fp != NULL) {
							char line[1024] = { 0 };

							fgets(line, sizeof(line), fp);
							fclose(fp);

							if (line[strlen(line) - 1] == '\n')
								line[strlen(line) - 1] = 0;

							oVal = strdup(line);
						}
					}
				}
				else
				if ((type != NULL) && (strncmp(type, "binary", 6) == 0)) {
					char line[4096] = { 0 };

					FILE *fp = popen(val, "r");
					if (fp != NULL) {
						fgets(line, sizeof(line), fp);

						if (line[strlen(line) - 1] == '\n')
							line[strlen(line) - 1] = 0;

						oVal = strdup(line);
					}
				}
				else
				if ((type != NULL) && (strncmp(type, "return-code", 11) == 0)) {
					if (access(val, X_OK) == 0) {
						int rv = -1;
						char *iarg = NULL;

						if (getAttribute(info.attr, "input") != NULL) {
							iarg = getAttribute(info.attr, "input");

							if (gUser != NULL) {
								oVal = replaceAll(iarg, "%USERNAME%", gUser);
								iarg = oVal;
							}
							if (gPassword != NULL) {
								oVal = replaceAll(iarg, "%PASSWORD%", gPassword);
								iarg = oVal;
							}
							if (gPlainPassword != NULL) {
								oVal = replaceAll(iarg, "%PLAINPASSWORD%", gPlainPassword);
								iarg = oVal;
							}
							oVal = iarg;

							int i;
							char tmp[1024] = { 0 };
							for (i = 0; i < nVars; i++) {
								if (gVars[i].sValue != NULL) {
									snprintf(tmp, sizeof(tmp), "%%%s%%", gVars[i].name);
									char *oVal2 = replaceAll(oVal, tmp, gVars[i].sValue);
									oVal = oVal2;
								}
							}

							char *oVal2 = replaceAll(oVal, "\\n", "\n");
							oVal = oVal2;

							DPRINTF("%s: Accessing '%s' ... \n",
								__FUNCTION__, val);

							FILE *fp = popen(val, "w");
							fprintf(fp, "%s", oVal);
							rv = WEXITSTATUS(pclose(fp));

							snprintf(tmp, sizeof(tmp), "%d", rv);
							oVal = strdup(tmp);
						}
					}
				}
				else
				if ((type != NULL) && (strncmp(type, "url", 3) == 0)) {
					oVal = replace(val, "%USERNAME%", gUser);
					val = replace(oVal, "%PASSWORD%", gPassword);
					oVal = val;

					int i;
					char tmp[1024] = { 0 };

					for (i = 0; i < nVars; i++) {
						if (gVars[i].sValue != NULL) {
							snprintf(tmp, sizeof(tmp), "%%%s%%", gVars[i].name);
							char *oVal2 = replace(oVal, tmp, gVars[i].sValue);
							oVal = oVal2;
						}
					}

					char *tmpO = curlRequest(oVal, NULL, CURL_SKIP_PEER_VERIFICATION);
					if (tmpO != NULL) {
						char line[1024] = { 0 };

						FILE *fp = fopen(tmpO, "r");
						fgets(line, sizeof(line), fp);
						fclose(fp);

						if (line[strlen(line) - 1] == '\n')
							line[strlen(line) - 1] = 0;

						unlink(tmpO);
						free(oVal);
						oVal = strdup(line);
					}
					else {
						free(oVal);
						oVal = NULL;
					}
				}
				else
				if ((type != NULL) && (strncmp(type, "input", 5) == 0)) {
					char *earg = getAttribute(info.attr, "echo");

					if (earg != NULL) {
						char tmp[1024] = { 0 };
						int echo = 0;
						if ((strcmp(earg, "true") == 0) || (strcmp(earg, "1") == 0))
							echo = 1;

						snprintf(tmp, sizeof(tmp), "%s: ", val);
						if ((oVal = getConversation(tmp, echo)) == NULL)
							gIsValid = gDocPAMErr;
					}
				}

				variableSave(output, oVal, 0, VAR_STR);

				//DPRINTF("%s: INSTRUCTION Read => type '%s', output: '%s', value: '%s'; oVal '%s'\n",
				//	__FUNCTION__, type, output, val, oVal);
			}
		}
		else
		if (strcmp(info.name, "env") == 0) {
			char tmp[1024] = { 0 };
			char *name = getAttribute(info.attr, "name");

			DPRINTF("%s: Setting environment variable '%s' with value '%s'\n",
				__FUNCTION__, name, val);

			snprintf(tmp, sizeof(tmp), "PAM_XML_%s=%s", name, val);
			pam_putenv(gPamh, tmp);
		}
		else
		if (strcmp(info.name, "return") == 0) {
			gIsValid = translate_pam_code(val);
			if (gIsValid == PAM_SERVICE_ERR) {
				if (strcmp(val, "success") == 0) {
					if (gRulesetAdd == 1) {
						char tmp[1024] = { 0 };
						snprintf(tmp, sizeof(tmp), "PAM_XML_RULESET=%s", gRuleset);
						pam_putenv(gPamh, tmp);
					}
					gIsValid = gDocPAMOK;
				}
				else
				if (strcmp(val, "error") == 0)
					gIsValid = gDocPAMErr;
			}

			DPRINTF("%s: Return command '%s', translated to %d", __FUNCTION__, val, gIsValid);
			shouldReturn = 1;
			goto end;
		}

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
	//DPRINTF("%s(path = '%s', block = '%s'): Returning value %d\n",
	//	__FUNCTION__, info.path, info.name, ret);
	goto real_end;
end:
	//DPRINTF("%s(path = '%s', name = '%s'): Returning value %d\n",
	//	__FUNCTION__, info.path, info.name, ret);
real_end:
	return ret;
}

