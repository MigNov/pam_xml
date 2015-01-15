#define DEBUG_MODULE

#define _GNU_SOURCE

#include "xml.h"

// (conversation function)
#define ____WITH_CONV

// pam_set_item, pam_get_item, pam_get_user
#define ____WITH_ITEM

// pam_putenv, pam_getenv, pam_getenvlist
#define ____WITH_ENV

// pam_set_data, pam_get_data
#define ____WITH_DATA

#ifdef DEBUG_MODULE
#define DPRINTF(fmt, ...) \
do { _log(0, "[pam_xml/module  ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

void initAll(void)
{
	gFn = NULL;
	gRuleset = NULL;
	gPlainPassword = NULL;
	gAlgo = NULL;
	gLogFile = NULL;
	gUser = NULL;
	gPassword = NULL;
	gIsValid = 0;
	gDocPAMOK = 0;
	gDocPAMErr = PAM_AUTH_ERR;
	shouldReturn = 0;
	nVars = 0;
	gRulesetAdd = 0;

	instruction.attr1 = NULL;
	instruction.attr2 = NULL;
	instruction.attr3 = NULL;
}

void freeAll(void)
{
	if (gFn != NULL)
		free(gFn);
	if (gRuleset != NULL)
		free(gRuleset);
	if (gPlainPassword != NULL)
		free(gPlainPassword);
	if (gAlgo != NULL)
		free(gAlgo);
	if (gLogFile != NULL)
		free(gLogFile);
	if (gUser != NULL)
		free(gUser);
	if (gPassword != NULL)
		free(gPassword);

	gFn = NULL;
	gRuleset = NULL;
	gPlainPassword = NULL;
	gAlgo = NULL;
	gLogFile = NULL;
	gUser = NULL;
	gPassword = NULL;
}

int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
	int retval ;
	struct pam_conv *conv ;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ; 
	if( retval==PAM_SUCCESS ) {
		retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
	}

	return retval ;
}

char *getConversation(char *prompt, int echo)
{
	int retval;

	char *input ;
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;

	/* setting up conversation call prompting for one-time code */
	pmsg[0] = &msg[0] ;
	msg[0].msg_style = (echo == 1) ? PAM_PROMPT_ECHO_ON :  PAM_PROMPT_ECHO_OFF;
	msg[0].msg = prompt;
	resp = NULL ;
	if( (retval = converse(gPamh, 1 , pmsg, &resp)) != PAM_SUCCESS ) {
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return NULL;
	}

	/* retrieving user input */
	if( resp ) {
		//if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
		if( resp[0].resp == NULL ) {
	    		free( resp );
	    		return NULL;
		}
		input = resp[ 0 ].resp;
		resp[ 0 ].resp = NULL; 		  				  
    	} else {
		return NULL;
	}

	return strdup(input);
}

char *hashMD5(char *string)
{
	int i;
	unsigned char digest[MD5_DIGEST_LENGTH];

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, string, strlen(string));
	MD5_Final(digest, &ctx);

	char mdString[MD5_DIGEST_LENGTH * 2 + 1];
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

	return strdup(mdString);
}

char *hashSHA1(char *string)
{
	int i;
	unsigned char digest[SHA_DIGEST_LENGTH];

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, string, strlen(string));
	SHA1_Final(digest, &ctx);

	char mdString[SHA_DIGEST_LENGTH * 2 + 1];
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

	return strdup(mdString);
}

char *hashSHA256(char *string)
{
	int i;
	unsigned char digest[SHA256_DIGEST_LENGTH];

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, string, strlen(string));
	SHA256_Final(digest, &ctx);

	char mdString[SHA256_DIGEST_LENGTH * 2 + 1];
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

	return strdup(mdString);
}

void _log(int inc, const char *format, ...)
{
	static int inclen = 0;
	va_list args;
	int fd, i;
	static char buffer[256];

	if (gLogFile == NULL)
		return;

	if (inc < 0)
		inclen += inc;
	if (inclen < 0) {
		inclen = 0;
		_log(0, "***** ERROR: inclen<0 in _log *****");
	}

	memset(buffer, ' ', inclen);
	i = inclen;

	va_start(args, format);
	i += vsprintf(&buffer[i], format, args);
	if (buffer[strlen(buffer) - 1] != '\n')
		buffer[i++] = '\n';
	va_end(args);

	if ((fd = open(gLogFile, O_WRONLY|O_NOFOLLOW|O_APPEND)) != -1) {
		write(fd, buffer, i);
		close(fd);
	}

	if (inc > 0)
		inclen += inc;
}

//----------------------------------------------------------------------------

#define TEST(mask)				\
	if (flags & mask) {			\
		strcat(buffer, #mask " ");	\
		flags = flags ^ mask;		\
	}

static char *pamflags (int flags)
{
	static char buffer[128];
	buffer[0] = '\0';

	TEST(PAM_SILENT)
	TEST(PAM_DISALLOW_NULL_AUTHTOK)
	TEST(PAM_ESTABLISH_CRED)
	TEST(PAM_DELETE_CRED)
	TEST(PAM_REINITIALIZE_CRED)
	TEST(PAM_REFRESH_CRED)
	TEST(PAM_CHANGE_EXPIRED_AUTHTOK)

	if (flags != 0) {
		char *buff = buffer + strlen(buffer);
		sprintf(buff, "    ** unknown flags: %i **", flags);
	}

	if (!buffer[0])
		strcpy(buffer, "(no flags)");

	return buffer;
}

#undef TEST

//----------------------------------------------------------------------------

#define TEST(value)				\
	case value :				\
		strcpy(buffer, #value);		\
		break;

static char *pamretval (int retval)
{
	static char buffer[128];

	switch (retval) {
	TEST(PAM_SUCCESS)
	TEST(PAM_OPEN_ERR)
	TEST(PAM_SYMBOL_ERR)
	TEST(PAM_SERVICE_ERR)
	TEST(PAM_SYSTEM_ERR)
	TEST(PAM_BUF_ERR)
	TEST(PAM_PERM_DENIED)
	TEST(PAM_AUTH_ERR)
	TEST(PAM_CRED_INSUFFICIENT)
	TEST(PAM_AUTHINFO_UNAVAIL)
	TEST(PAM_USER_UNKNOWN)
	TEST(PAM_MAXTRIES)
	TEST(PAM_NEW_AUTHTOK_REQD)
	TEST(PAM_ACCT_EXPIRED)
	TEST(PAM_SESSION_ERR)
	TEST(PAM_CRED_UNAVAIL)
	TEST(PAM_CRED_EXPIRED)
	TEST(PAM_CRED_ERR)
	TEST(PAM_NO_MODULE_DATA)
	TEST(PAM_CONV_ERR)
	TEST(PAM_AUTHTOK_ERR)
	TEST(PAM_AUTHTOK_RECOVER_ERR)
	TEST(PAM_AUTHTOK_LOCK_BUSY)
	TEST(PAM_AUTHTOK_DISABLE_AGING)
	TEST(PAM_TRY_AGAIN)
	TEST(PAM_IGNORE)
	TEST(PAM_ABORT)
	TEST(PAM_AUTHTOK_EXPIRED)
	TEST(PAM_MODULE_UNKNOWN)
	TEST(PAM_BAD_ITEM)
	TEST(PAM_CONV_AGAIN)
	TEST(PAM_INCOMPLETE)

	default :
		sprintf(buffer, "** unknown return value: %i **", retval);
	}

	return buffer;
}

#undef TEST

//----------------------------------------------------------------------------

#ifdef ____WITH_CONV

static int pamconv (int num_msg, const struct pam_message **msg,
		    struct pam_response **resp, void *appdata_ptr)
{
	int retval, i;
	struct pam_conv *origconv = (struct pam_conv *) appdata_ptr;
	char buffer[256];

	_log( 0, "pamconv c%8.8X       %i",
			origconv, num_msg);

	for (i=0; i<num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF :
			sprintf(buffer, "%i - PAM_PROMPT_ECHO_OFF - \"%s\"",
					i, msg[i]->msg);
			break;
		case PAM_PROMPT_ECHO_ON :
			sprintf(buffer, "%i - PAM_PROMPT_ECHO_ON - \"%s\"",
					i, msg[i]->msg);
			break;
		case PAM_ERROR_MSG :
			sprintf(buffer, "%i - PAM_ERROR_MSG - \"%s\"",
					i, msg[i]->msg);
			break;
		case PAM_TEXT_INFO :
			sprintf(buffer, "%i - PAM_TEXT_INFO - \"%s\"",
					i, msg[i]->msg);
			break;
		case PAM_RADIO_TYPE :
			sprintf(buffer, "%i - PAM_RADIO_TYPE - "
					"(how to display?)",
					i);
			break;
		case PAM_BINARY_PROMPT :
			sprintf(buffer, "%i - PAM_BINARY_PROMPT - "
					"(binary data)",
					i);
			break;
		default :
			sprintf(buffer, "%i - unknown message style %i",
					i, msg[i]->msg_style);
		}
		if (i == num_msg - 1) {
			_log( 4, "                        msg  %s",
					buffer);
		} else {
			_log( 0, "                        msg  %s",
					buffer);
		}
	}

	retval = (origconv->conv(num_msg, msg, resp, origconv->appdata_ptr));

	if (retval != PAM_SUCCESS) {
		_log(-4, "                        %s",
				pamretval(retval));

		return retval;
	}

	for (i=0; i<num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF :
			sprintf(buffer, "%i - %u - (string not shown)",
					i, (*resp)[i].resp_retcode);
			//sprintf(buffer, "%i - %u - \"%s\"",
			//		i, (*resp)[i].resp_retcode,
			//		(*resp)[i].resp);
			break;
		case PAM_PROMPT_ECHO_ON :
		case PAM_ERROR_MSG :
		case PAM_TEXT_INFO :
			sprintf(buffer, "%i - %u - \"%s\"",
					i, (*resp)[i].resp_retcode,
					(*resp)[i].resp);
			break;
		case PAM_RADIO_TYPE :
			sprintf(buffer, "%i - %u - (how to display?)",
					i, (*resp)[i].resp_retcode);
			break;
		case PAM_BINARY_PROMPT :
			sprintf(buffer, "%i - %u - (binary data)",
					i, (*resp)[i].resp_retcode);
			break;
		default :
			sprintf(buffer, "%i - %u - unknown message style %i",
					i, (*resp)[i].resp_retcode, 
					msg[i]->msg_style);
		}
		if (i == 0) {
			_log(-4, "                        resp %s",
					buffer);
		} else {
			_log( 0, "                        resp %s",
					buffer);
		}
	}
	_log( 0, "                        %s",
			pamretval(retval));

	return retval;
}

static struct pam_conv *pamconv_prep (const struct pam_conv *origconv)
{
	struct pam_conv *retval;

	retval = (struct pam_conv *) malloc(sizeof(struct pam_conv));
	if (!retval) {
		printf("***** ERROR:  out of memory *****");
		exit(EXIT_FAILURE);
	}

//	_log( 0, "pamconv_prep");

	retval -> conv = pamconv;
	retval -> appdata_ptr = (struct pam_conv *) origconv;

	return retval;
}

#else // ____WITH_CONV

static struct pam_conv *pamconv_prep (const struct pam_conv *origconv)
{
	return (struct pam_conv *) origconv;
}

#endif // ____WITH_CONV

//----------------------------------------------------------------------------

#define interpose_prep(f) 					\
	static int (*func) ();					\
	if (!func) {						\
		func = (int (*)()) dlsym(RTLD_NEXT, f);	\
		if (!func) {					\
			printf("*** wrapper error *** "		\
			       "function " f " not found\n");	\
			exit(EXIT_FAILURE);			\
		}						\
	}

//----------------------------------------------------------------------------

int pam_start (const char *service_name, const char *user, 
	       const struct pam_conv *pam_conversation, 
	       pam_handle_t **pamh)
{	
	int retval;
	interpose_prep("pam_start");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_start               \"%s\" / \"%s\" / c%8.8X",
			service_name, user, pam_conversation);

	retval = (func (service_name, user, pamconv_prep(pam_conversation),
				pamh));

	_log(-4, "                        %s / h%8.8X",
			pamretval(retval), *pamh);

	return retval;
}

int pam_end (pam_handle_t *pamh, int pam_status)
{
	int retval;
	interpose_prep("pam_end");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_end                 h%8.8X / %i",
			pamh, pam_status);

	retval = (func (pamh, pam_status));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_authenticate(pam_handle_t *pamh, int flags)
{
	int retval;
	interpose_prep("pam_authenticate");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_authenticate        h%8.8X / %s",
			pamh, pamflags(flags));

	retval = (func (pamh, flags));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_setcred(pam_handle_t *pamh, int flags)
{
	int retval;
	interpose_prep("pam_setcred");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_setcred             h%8.8X / %s",
			pamh, pamflags(flags));

	retval = (func (pamh, flags));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	int retval;
	interpose_prep("pam_acct_mgmt");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_acct_mgmt           h%8.8X / %s",
			pamh, pamflags(flags));

	retval = (func (pamh, flags));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_open_session(pam_handle_t *pamh, int flags)
{
	int retval;
	interpose_prep("pam_open_session");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_open_session        h%8.8X / %s",
			pamh, pamflags(flags));

	retval = (func (pamh, flags));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_close_session(pam_handle_t *pamh, int flags)
{
	int retval;
	interpose_prep("pam_close_session");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_close_session       h%8.8X / %s",
			pamh, pamflags(flags));

	retval = (func (pamh, flags));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_chauthtok(pam_handle_t *pamh, int flags)
{
	int retval;
	interpose_prep("pam_chauthtok");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_chauthtok           h%8.8X / %s",
			pamh, pamflags(flags));

	retval = (func (pamh, flags));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_fail_delay(pam_handle_t *pamh, unsigned int musec_delay)
{
	int retval;
	interpose_prep("pam_fail_delay");

	DPRINTF("%s: Enter\n", __FUNCTION__);

	_log( 4, "pam_fail_delay          h%8.8X / %u",
			pamh, musec_delay);

	retval = (func (pamh, musec_delay));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

//----------------------------------------------------------------------------

#ifdef ____WITH_ITEM

#define TEST(value)				\
	case value :				\
		strcpy(buffer, #value);		\
		break;

static char *pamitems (int item)
{
	static char buffer[128];

	switch(item) {
	TEST(PAM_SERVICE)
	TEST(PAM_USER)
	TEST(PAM_TTY)
	TEST(PAM_RHOST)
	TEST(PAM_CONV)
	TEST(PAM_AUTHTOK)
	TEST(PAM_OLDAUTHTOK)
	TEST(PAM_RUSER)
	TEST(PAM_USER_PROMPT)
	TEST(PAM_FAIL_DELAY)

	default :
		sprintf(buffer, "** unknown item: %i **", item);
	}

	return buffer;
}

#undef TEST

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
	int retval;
	const char *s;
	char buffer[256];
	struct pam_conv *conv;
	interpose_prep("pam_set_item");

	switch (item_type) {
	case PAM_SERVICE :
	case PAM_USER :
	case PAM_TTY :
	case PAM_RHOST :
	case PAM_RUSER :
	case PAM_USER_PROMPT :
		sprintf(buffer, "\"%s\"", item);
		s = buffer;
		break;

	case PAM_CONV :
		conv = (struct pam_conv *) item;
		sprintf(buffer, "c%8.8X", conv);
		s = buffer;
		item = (const void *) pamconv_prep(conv);
		break;

	case PAM_FAIL_DELAY :
		sprintf(buffer, "p%8.8X", item);
		s = buffer;
		break;

	case PAM_AUTHTOK :
	case PAM_OLDAUTHTOK :
		if (item == NULL) {
			strcpy(buffer, "(null)");
			s = buffer;
		} else {
			strcpy(buffer, "(string not shown)");
			//strcpy(buffer, item);
			s = buffer;
		}
		break;

	default :
		strcpy(buffer, "** unknown item type **");
		s = buffer;
	}

	_log( 4, "pam_set_item            h%8.8X / %s / %s",
			pamh, pamitems(item_type), s);

	retval = (func (pamh, item_type, item));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
	int retval;
	const char *s;
	char buffer[256];
	struct pam_conv *conv;
	interpose_prep("pam_get_item");

	_log( 4, "pam_get_item            h%8.8X / %s",
			pamh, pamitems(item_type));

	retval = (func (pamh, item_type, item));

	switch (item_type) {
	case PAM_SERVICE :
	case PAM_USER :
	case PAM_TTY :
	case PAM_RHOST :
	case PAM_RUSER :
	case PAM_USER_PROMPT :
		sprintf(buffer, "\"%s\"", *item);
		s = buffer;
		break;

	case PAM_CONV :
		conv = (struct pam_conv *) *item;
#ifdef ____WITH_CONV
		sprintf(buffer, "c%8.8X", conv->appdata_ptr);
#else
		sprintf(buffer, "c%8.8X", conv);
#endif
		s = buffer;
		break;

	case PAM_FAIL_DELAY :
		sprintf(buffer, "p%8.8X", *item);
		s = buffer;
		break;
	
	case PAM_AUTHTOK :
	case PAM_OLDAUTHTOK :
		if (item == NULL) {
			strcpy(buffer, "(null)");
			s = buffer;
		} else {
			strcpy(buffer, "(string not shown)");
			//strcpy(buffer, *item);
			s = buffer;
		}
		break;

	default :
		strcpy(buffer, "** unknown item type **");
		s = buffer;
	}

	_log(-4, "                        %s / %s",
			pamretval(retval), s);

	return retval;
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
	int retval;
	interpose_prep("pam_get_user");

	_log( 4, "pam_get_user            h%8.8X / \"%s\"",
			pamh, prompt);

	retval = (func (pamh, user, prompt));

	_log(-4, "                        %s / \"%s\"",
			pamretval(retval), *user);

	return retval;
}

#endif // ____WITH_ITEM

//----------------------------------------------------------------------------

#ifdef ____WITH_ENV

int pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	int retval;
	interpose_prep("pam_putenv");

	_log( 4, "pam_putenv              h%8.8X / \"%s\"",
			pamh, name_value);

	retval = (func (pamh, name_value));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

const char *pam_getenv(pam_handle_t *pamh, const char *name)
{
	const char *retval;
	static const char * (*func) ();
	if (!func) {
		func = (const char * (*)()) dlsym(RTLD_NEXT, "pam_getenv");
		if (!func) {
			printf("*** wrapper error *** "
			       "function pam_getenv not found\n");
			exit(EXIT_FAILURE);
		}
	}

	_log( 4, "pam_getenv              h%8.8X / \"%s\"",
			pamh, name);

	retval = (func (pamh, name));

	_log(-4, "                        \"%s\"",
			retval);

	return retval;
}

char **pam_getenvlist(pam_handle_t *pamh)
{
	char **retval;
	static char ** (*func) ();
	if (!func) {
		func = (char ** (*)()) dlsym(RTLD_NEXT, "pam_getenvlist");
		if (!func) {
			printf("*** wrapper error *** "
			       "function pam_getenvlist not found\n");
			exit(EXIT_FAILURE);
		}
	}

	_log( 4, "pam_getenvlist          h%8.8X",
			pamh);

	retval = (func (pamh));

	_log(-4, "                        p%8.8X",
			retval);

	return retval;
}

#endif // ____WITH_ENV

//----------------------------------------------------------------------------

#ifdef ____WITH_DATA

int pam_set_data(pam_handle_t *pamh, const char *module_data_name, void *data,
		 void (*cleanup)(pam_handle_t *pamh, void *data, 
			         int error_status))
{
	int retval;
	interpose_prep("pam_set_data");

	_log( 4, "pam_set_data            h%8.8X / \"%s\" / p%8.8X / p%8.8X",
			pamh, module_data_name, data, cleanup);

	retval = (func (pamh, module_data_name, data, cleanup));

	_log(-4, "                        %s",
			pamretval(retval));

	return retval;
}

int pam_get_data(const pam_handle_t *pamh, const char *module_data_name,
		 const void **data)
{
	int retval;
	interpose_prep("pam_get_data");

	_log( 4, "pam_get_data            h%8.8X / \"%s\"",
			pamh, module_data_name);

	retval = (func (pamh, module_data_name, data));

	_log(-4, "                        %s / p%8.8X",
			pamretval(retval), *data);

	return retval;
}

#endif // ____WITH_DATA

void dumpArgs(const char *func, int argc, const char **argv)
{
	int i;

	DPRINTF("[dumpArgs] %s args: %d", func, argc);

	for (i = 0; i < argc; i++)
		DPRINTF("[dumpArgs] %s arg[%d]: %s", func, i, argv[i]);
}

int algGetType(char *name)
{
	int ret = -1;

	if ((strcmp(name, "none") == 0) || (strcmp(name, "disable") == 0))
		ret = 0;
	if ((strcmp(name, "md5") == 0) || ((strcmp(name, "MD5") == 0)))
		ret = 1;
	if ((strcmp(name, "sha1") == 0) || ((strcmp(name, "SHA1") == 0)))
		ret = 2;
	if ((strcmp(name, "sha256") == 0) || ((strcmp(name, "SHA256") == 0)))
		ret = 3;

	DPRINTF("%s('%s') returned %d", __FUNCTION__, name, ret);
	return ret;
}

int isAlgoSupported(char *name)
{
	int ret = algGetType(name) > 0 ? 1 : 0;

	DPRINTF("%s('%s') returned %d", __FUNCTION__, name, ret);
	return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags
               ,int argc, const char **argv)
{
	unsigned int ctrl;
	int retval;
	const char *name, *p;
	char *finalFileDel = NULL;

	gPamh = pamh;

	initAll();

	retval = pam_get_user(pamh, &name, "login: ");
	if (retval != PAM_SUCCESS) {
		DPRINTF("%s: Error reading username = %s", __FUNCTION__, pamretval(retval));
		return retval;
	}

	gRulesetAdd = 0;
	if (argc > 0) {
		int i;
		for (i = 0; i < argc; i++) {

			if (strncmp(argv[i], "ruleset=", 8) == 0) {
				gRuleset = strdup(argv[i] + 8);
				gFn = strdup(argv[i] + 8);
			}
			if (strncmp(argv[i], "algo=", 5) == 0) {
				if (!isAlgoSupported(argv[i] + 5)) {
					printf("Invalid configuration. Algorithm set is not supported.\n");
					freeAll();
					return PAM_AUTHINFO_UNAVAIL;
				}
				gAlgo = strdup(argv[i] + 5);
			}
			if (strncmp(argv[i], "logfile=", 8) == 0)
				gLogFile = strdup(argv[i] + 8);
			if (strncmp(argv[i], "envruleset", 10) == 0)
				gRulesetAdd = 1;
		}
	}

	if (gFn == NULL) {
		DPRINTF("%s: Ruleset file not set. Ignoring module ... ", __FUNCTION__);
		freeAll();
		return PAM_IGNORE;
	}

	if (strncmp(gFn, "http", 4) == 0) {
		DPRINTF("%s: Accessing URL '%s' to download ruleset ...\n", __FUNCTION__, gFn);

		gFn = curlRequest(gFn, NULL, CURL_SKIP_PEER_VERIFICATION);
		if (gFn != NULL) {
			finalFileDel = strdup(gFn);

			DPRINTF("%s: Ruleset saved locally to '%s' ...\n", __FUNCTION__, gFn);
		}
	}

	if (gFn == NULL) {
		DPRINTF("%s: Cannot access ruleset file ... ", __FUNCTION__);
		freeAll();
		return PAM_AUTHINFO_UNAVAIL;
	}

	if (access(gFn, R_OK) != 0) {
		DPRINTF("%s: Ruleset file '%s' cannot be read. Ignoring module ... ", __FUNCTION__, gFn);
		freeAll();
		return PAM_IGNORE;
	}

	DPRINTF("%s: Ruleset file is '%s'", __FUNCTION__, gFn);

	const char *user;
	char *password, *pwd = NULL;
	pam_get_user (pamh, &user, NULL);
	pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&password, NULL);

	switch (algGetType(gAlgo)) {
		case 0: pwd = password;
			break;
		case 1: pwd = hashMD5(password);
			break;
		case 2: pwd = hashSHA1(password);
			break;
		case 3: pwd = hashSHA256(password);
			break;
	}

	gPlainPassword = strdup(password);

	DPRINTF("UserInfo = { name: '%s', password: '%s', password-algo: '%s' }", user, pwd, gAlgo);

	gUser = strdup(user);
	gPassword = strdup(pwd);

	processXml(gFn);

	//DPRINTF("pam_sm_authenticate: %s", pamflags(flags));

	dumpArgs(__FUNCTION__, argc, argv);

	DPRINTF("%s: Returning value %d\n", __FUNCTION__, gIsValid);
	freeAll();

	if (finalFileDel != NULL)
		unlink(finalFileDel);

	return gIsValid;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	DPRINTF("%s: %s", __FUNCTION__, pamflags(flags));

	dumpArgs(__FUNCTION__, argc, argv);
	freeAll();
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	DPRINTF("%s: %s", __FUNCTION__, pamflags(flags));

	dumpArgs(__FUNCTION__, argc, argv);
	freeAll();
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, const int flags, int argc, const char **argv)
{
	DPRINTF("%s: %s", __FUNCTION__, pamflags(flags));

	dumpArgs(__FUNCTION__, argc, argv);
	freeAll();
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, const int flags, int argc, const char **argv)
{
	DPRINTF("%s: %s", __FUNCTION__, pamflags(flags));

	dumpArgs(__FUNCTION__, argc, argv);
	freeAll();
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, const int flags, int argc, const char **argv)
{
	DPRINTF("%s: %s", __FUNCTION__, pamflags(flags));

	dumpArgs(__FUNCTION__, argc, argv);
	freeAll();
	return PAM_IGNORE;
}

#ifdef STANDALONE_APP
int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Syntax: %s <filename>\n", argv[0]);
		return EXIT_FAILURE;
	}

	processXml(argv[1]);
	return 0;
}
#endif
