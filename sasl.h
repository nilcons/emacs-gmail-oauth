/* Simplified sasl.h together with saslplug.h, so we don't depend on /usr/include */

#define SASL_FEAT_WANT_CLIENT_FIRST 0x0002
#define SASL_FEAT_ALLOWS_PROXY      0x0020
#define SASL_CLIENT_PLUG_VERSION    4
#define SASL_CONTINUE               1
#define SASL_OK                     0
#define SASL_FAIL                   -1
#define SASL_INTERACT               2
#define SASL_BADVERS                -23
#define SASL_CB_LIST_END            0
#define SASL_CB_AUTHNAME            0x4002
#define SASL_CU_AUTHID              0x01
#define SASL_CU_AUTHZID             0x02
#define SASL_SEC_MAXIMUM            0x00FF

typedef int sasl_getsimple_t(void *context, int id, const char **result, unsigned *len);
typedef unsigned sasl_ssf_t;
typedef struct sasl_conn sasl_conn_t;
typedef struct sasl_callback sasl_callback_t;
typedef struct sasl_security_properties {
  sasl_ssf_t min_ssf;
  sasl_ssf_t max_ssf;
  unsigned maxbufsize;
  unsigned security_flags;
  const char **property_names;
  const char **property_values;
} sasl_security_properties_t;
typedef struct sasl_interact {
    unsigned long id;
    const char *challenge;
    const char *prompt;
    const char *defresult;
    const void *result;
    unsigned len;
} sasl_interact_t;

typedef int (*sasl_callback_ft)(void);
typedef int sasl_getcallback_t(sasl_conn_t *conn,
                               unsigned long callbackid,
                               sasl_callback_ft * pproc,
                               void **pcontext);
typedef struct sasl_utils {
  int version;
  sasl_conn_t *conn;
  void *rpool;
  void *getopt_context;
  void (*getopt)(void);
  void *(*malloc)(size_t);
  void (*calloc)(void);
  void (*realloc)(void);
  void (*free)(void *);
  void (*mutex_alloc)(void);
  void (*mutex_lock)(void);
  void (*mutex_unlock)(void);
  void (*mutex_free)(void);
  void (*MD5Init)(void);
  void (*MD5Update)(void);
  void (*MD5Final)(void);
  void (*hmac_md5)(void);
  void (*hmac_md5_init)(void);
  void (*hmac_md5_final)(void);
  void (*hmac_md5_precalc)(void);
  void (*hmac_md5_import)(void);
  int (*mkchal)(void);
  int (*utf8verify)(void);
  void (*rand)(void);
  void (*churn)(void);
  int (*checkpass)(sasl_conn_t *conn, const char *user, unsigned userlen, const char *pass, unsigned passlen);
  int (*decode64)(const char *in, unsigned inlen, char *out, unsigned outmax, unsigned *outlen);
  int (*encode64)(const char *in, unsigned inlen, char *out, unsigned outmax, unsigned *outlen);
  void (*erasebuffer)(char *buf, unsigned len);
  int (*getprop)(sasl_conn_t *conn, int propnum, const void **pvalue);
  int (*setprop)(sasl_conn_t *conn, int propnum, const void *value);
  sasl_getcallback_t *getcallback;
  void (*log)(sasl_conn_t *conn, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
  void (*seterror)(sasl_conn_t *conn, unsigned flags, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
  int *(*spare_fptr)(void);
} sasl_utils_t;

struct iovec;
typedef struct sasl_out_params {
    unsigned doneflag;

    const char *user;		/* canonicalized user name */
    const char *authid;		/* canonicalized authentication id */

    unsigned ulen;		/* length of canonicalized user name */
    unsigned alen;		/* length of canonicalized authid */

    /* security layer information */
    unsigned maxoutbuf;         /* Maximum buffer size, which will
                                   produce buffer no bigger than the
                                   negotiated SASL maximum buffer size */
    sasl_ssf_t mech_ssf;   /* Should be set non-zero if negotiation of a
                            * security layer was *attempted*, even if
                            * the negotiation failed */
    void *encode_context;
    int (*encode)(void *context, const struct iovec *invec, unsigned numiov,
                  const char **output, unsigned *outputlen);
    void *decode_context;
    int (*decode)(void *context, const char *input, unsigned inputlen,
                  const char **output, unsigned *outputlen);

    /* Pointer to delegated (client's) credentials, if supported by
       the SASL mechanism */
    void *client_creds;

    /* for additions which don't require a version upgrade; set to 0 */
    const void *gss_peer_name;
    const void *gss_local_name;
    const char *cbindingname;   /* channel binding name from packet */
    int (*spare_fptr1)(void);
    int (*spare_fptr2)(void);
    unsigned int cbindingdisp;  /* channel binding disposition from client */
    int spare_int2;
    int spare_int3;
    int spare_int4;

    /* set to 0 initially, this allows a plugin with extended parameters
     * to work with an older framework by updating version as parameters
     * are added.
     */
    int param_version;
} sasl_out_params_t;

typedef struct sasl_client_params {
  const char *service;
  const char *serverFQDN;
  const char *clientFQDN;
  const sasl_utils_t *utils;
  const sasl_callback_t *prompt_supp;
  const char *iplocalport;
  const char *ipremoteport;
  unsigned servicelen;
  unsigned slen;
  unsigned clen;
  unsigned iploclen;
  unsigned ipremlen;
  sasl_security_properties_t props;
  sasl_ssf_t external_ssf;
  const void *gss_creds;
  void *cbinding;
  void *http_request;
  void *spare_ptr4;
  int (*canon_user)(sasl_conn_t *conn,
                    const char *in, unsigned len,
                    unsigned flags,
                    sasl_out_params_t *oparams);
  int (*spare_fptr1)(void);
  unsigned int cbindingdisp;
  int spare_int2;
  int spare_int3;
  unsigned flags;
  int param_version;
} sasl_client_params_t;

typedef struct sasl_client_plug {
    const char *mech_name;
    sasl_ssf_t max_ssf;
    unsigned security_flags;
    unsigned features;
    const unsigned long *required_prompts;
    void *glob_context;
    int (*mech_new)(void *glob_context,
                    sasl_client_params_t *cparams,
                    void **conn_context);
    int (*mech_step)(void *conn_context,
                     sasl_client_params_t *cparams,
                     const char *serverin,
                     unsigned serverinlen,
                     sasl_interact_t **prompt_need,
                     const char **clientout,
                     unsigned *clientoutlen,
                     sasl_out_params_t *oparams);
    void (*mech_dispose)(void *conn_context, const sasl_utils_t *utils);
    void (*mech_free)(void *glob_context, const sasl_utils_t *utils);
    int (*idle)(void *glob_context,
                void *conn_context,
                sasl_client_params_t *cparams);
    int (*spare_fptr1)(void);
    int (*spare_fptr2)(void);
} sasl_client_plug_t;
