#include <stddef.h>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>
/* #include "sasl.h" */

typedef struct File FILE;
extern int fprintf(FILE*, const char*, ...);
extern FILE *stderr;
extern char *getenv(const char*);

#include <stdlib.h>

static int client_mech_new(void *glob_context,
                           sasl_client_params_t *params,
                           void **conn_context) {
  return SASL_OK;
}

static void client_mech_dispose(void *conn_context, const sasl_utils_t *utils) {
}

static sasl_interact_t oauthenv_interact_template[] =
  {
   { SASL_CB_AUTHNAME, NULL, NULL, NULL, NULL, 0 },
   { SASL_CB_LIST_END, NULL, NULL, NULL, NULL, 0 }
  };

static char oauthenv_env_prefix[] = "OAUTHENV_TOKEN_";

static char oauthenv_missing_envvar[] = " environment variable missing!";

static int client_mech_step(void *conn_context,
                            sasl_client_params_t *params,
                            const char *serverin,
                            unsigned serverinlen,
                            sasl_interact_t **interact,
                            const char **clientout,
                            unsigned *clientoutlen,
                            sasl_out_params_t *oparams) {
  char env[256];
  const char * authname;
  unsigned authname_len;
  sasl_getsimple_t *simple_cb;
  void *simple_context;
  int has_authname = SASL_FAIL;

#ifdef OAUTHENV_DEBUG
  fprintf(stderr, "OAUTH_ENV sasl step! %s %s %s %u\n", serverin, oparams->authid, *clientout, oparams->doneflag);
#endif

  // In case of OAUTHBEARER, serverin definitely means error, because
  // the protocol is client-first without server response, and RFC
  // 7628 says, that a server response is definitely an error.
  if (serverin) {
    params->utils->seterror(params->utils->conn, 0, serverin);
    oparams->doneflag = 1;
    *clientout = NULL;
    *clientoutlen = 0;
    fprintf(stderr, "we failed!\n");
    return SASL_FAIL;
  }

  // If we are called a second time (oparams->authid) set, but we
  // didn't have a serverin, then we successfully authenticated.
  if (oparams->authid) {
    oparams->doneflag = 1;
    fprintf(stderr, "from the inside: %p %p\n", clientout, *clientout);
    *clientout = NULL;
    *clientoutlen = 0;
    return SASL_OK;
  }

#ifdef OAUTHENV_DEBUG
  if (params->utils->malloc == NULL ||
      params->utils->free == NULL) {
    params->utils->seterror(params->utils->conn, 0, "OAUTH_ENV: sasl's malloc or free is not provided");
  }
#endif

  if (interact != NULL && *interact != NULL) {
    sasl_interact_t *interact_iter = *interact;
    // We asked for AUTHNAME before, here is the interact answer
#ifdef OAUTHENV_DEBUG
    fprintf(stderr, "we interacted, let's see!\n");
#endif
    for (int finished = 0; !finished; ++interact_iter) {
      switch (interact_iter->id) {
      case SASL_CB_LIST_END:
#ifdef OAUTHENV_DEBUG
        fprintf(stderr, "end of interaction results!\n");
#endif
        finished = 1;
        break;
      case SASL_CB_AUTHNAME:
        if (interact_iter->len > 0) {
          authname_len = interact_iter->len;
          authname = (char*) interact_iter->result;
#ifdef OAUTHENV_DEBUG
          fprintf(stderr, "interaction result: %ld %s\n", interact_iter->id, (char*) interact_iter->result);
#endif
          has_authname = SASL_OK;
        }
        break;
      }
    }
    params->utils->free(*interact);
  } else {
    // First run, not a return of interact: try SASL callback to get AUTHNAME
    has_authname =
      params->utils->getcallback(params->utils->conn,
                                 SASL_CB_AUTHNAME,
                                 (sasl_callback_ft *) &simple_cb,
                                 &simple_context);
    if (has_authname == SASL_OK) {
      has_authname = simple_cb(simple_context, SASL_CB_AUTHNAME, &authname, &authname_len);
    }

    if (has_authname == SASL_INTERACT) {
#ifdef OAUTHENV_DEBUG
      fprintf(stderr, "callback says we should interact, let's do it!\n");
#endif
      *interact = params->utils->malloc(sizeof(oauthenv_interact_template));
      __builtin_memcpy(*interact, oauthenv_interact_template, sizeof(oauthenv_interact_template));
      return SASL_INTERACT;
    }
  }

  if (has_authname != SASL_OK) {
    params->utils->seterror(params->utils->conn, 0, "OAUTH_ENV: couldn't determine username");
    return SASL_FAIL;
  }

  if (SASL_OK != params->canon_user(params->utils->conn, authname, authname_len, SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams)) {
#ifdef OAUTHENV_DEBUG
    fprintf(stderr, "Problem during canon_user\n");
#endif
    params->utils->seterror(params->utils->conn, 0, "OAUTH_ENV: problem during canon_user");
    return SASL_FAIL;
  }

  if (authname_len > 128) {
    params->utils->seterror(params->utils->conn, 0, "OAUTH_ENV: AUTHNAME too long");
    return SASL_FAIL;
  }

  __builtin_memcpy(env, oauthenv_env_prefix, sizeof(oauthenv_env_prefix) - 1);
  __builtin_memcpy(env + sizeof(oauthenv_env_prefix) - 1, authname, authname_len);
  env[sizeof(oauthenv_env_prefix) + authname_len - 1] = 0;
#ifdef OAUTHENV_DEBUG
  fprintf(stderr, "envvar: %s\n", env);
#endif
  const char *token = getenv(env);
  if (token == NULL) {
    __builtin_memcpy(env + sizeof(oauthenv_env_prefix) + authname_len - 1, oauthenv_missing_envvar, sizeof(oauthenv_missing_envvar) - 1);
    env[sizeof(oauthenv_env_prefix) + authname_len + sizeof(oauthenv_missing_envvar) - 2] = 0;
    params->utils->seterror(params->utils->conn, 0, env);
    return SASL_FAIL;
  }
#ifdef OAUTHENV_DEBUG
  fprintf(stderr, "token: %s\n", token);
#endif
  *clientout = token;
  *clientoutlen = __builtin_strlen(token);

  return SASL_CONTINUE;
}

static sasl_client_plug_t client_plugins[] =
  {
   {
    "OAUTHBEARER",
    0,
    SASL_SEC_MAXIMUM,
    SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY,
    NULL,
    NULL,
    &client_mech_new,
    &client_mech_step,
    &client_mech_dispose,
    NULL,
    NULL,
    NULL,
    NULL
   }
  };

int sasl_client_plug_init(const sasl_utils_t *utils,
                          int maxversion,
                          int *out_version,
                          sasl_client_plug_t **pluglist,
                          int *plugcount) {
  if (maxversion < SASL_CLIENT_PLUG_VERSION) {
    utils->seterror(utils->conn, 0, "OAUTH_ENV: Version mismatch");
    return SASL_BADVERS;
  }
  *out_version = SASL_CLIENT_PLUG_VERSION;
  *pluglist = client_plugins;
  *plugcount = 1;
#ifdef OAUTHENV_DEBUG
  fprintf(stderr, "OAUTH_ENV initialized!\n");
#endif
  return SASL_OK;
}
