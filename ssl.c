/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "ssl.h"
#include "log.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>

#define TLS_method SSLv23_method

/* https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl */

extern const char *certificate_chain_file;
extern const char *private_key_file;
extern int use_ssl;

SSL_CTX *ssl_ctx = NULL;
static EVP_PKEY *pkey = NULL; /* private key */
static X509     *x509 = NULL; /* certificate */
static RSA      *rsa = NULL;

static void generate_cert_key()
{
        X509_NAME *x509_name;
        pkey = EVP_PKEY_new();

        if(!pkey) {
                fprintf(stderr, "TLS/SSL: Can not allocate EVP_PKEY \n");
                return;
        }
        
        rsa = RSA_generate_key(
                2048,   /* number of bits for the key - 2048 is a sensible value */
                RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
                NULL,   /* callback - can be NULL if we aren't displaying progress */
                NULL    /* callback argument - not needed in this case */
                );      /* The RSA structure will be automatically freed when the EVP_PKEY structure is freed */
      

        if(!EVP_PKEY_assign_RSA(pkey, rsa)) {
                fprintf(stderr, "TLS/SSL: Can not generate and assign RSA key. Error: %lu\n", ERR_get_error());
                free_ssl();
                return;
        }

        x509 = X509_new();
        
        if(!x509) {
                fprintf(stderr, "TLS/SSL: Can not allocates and initializes a X509 structure. Error: %lu\n", ERR_get_error());
                free_ssl();
                return;
        }

        srand(time(NULL));
        ASN1_INTEGER_set(X509_get_serialNumber(x509), rand()); 
        
        /* This certificate is valid from now until exactly one year from now. */
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
        
        /* set the public key for our certificate */
        X509_set_pubkey(x509, pkey);
        
        /* fill in some fields of name */
        x509_name = X509_get_subject_name(x509);
        if(!x509_name)
        {
                free_ssl();
                return;
        }
        X509_NAME_add_entry_by_txt(x509_name, "C",  MBSTRING_ASC,
                                   (unsigned char *)"RU", -1, -1, 0);
        X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC,
                                   (unsigned char *)"localhost", -1, -1, 0);
/*
        X509_NAME_add_entry_by_txt(x509_name, "subjectAltName", MBSTRING_ASC,
                                   (unsigned char *)"IP:localhost", -1, -1, 0);
*/
        X509_NAME_add_entry_by_txt(x509_name, "subjectAltName", MBSTRING_ASC,
                                   (unsigned char *)"DNS:localhost", -1, -1, 0);
        X509_set_issuer_name(x509, x509_name);
        
        /* sign our certificate */
        if(!X509_sign(x509, pkey, EVP_sha512())) {        
                fprintf(stderr, "TLS/SSL: Error signing certificate\n");
                free_ssl();
        }
}

void free_ssl()
{
        if(pkey) {
                EVP_PKEY_free(pkey);
debug_msg("freed pkey !!!!!!!!!!!");
                pkey = NULL;
        }
        if(x509) {
                X509_free(x509);
debug_msg("freed x509 !!!!!!!!!!!");
                x509 = NULL;
        }
        if(ssl_ctx) {
                SSL_CTX_free(ssl_ctx);
debug_msg("freed ssl_ctx !!!!!!!!!!!");
                ssl_ctx = NULL;
        }
/*
        if(rsa) {
                RSA_free(rsa);
debug_msg("freed rsa !!!!!!!!!!!");
                rsa = NULL;
        }
*/
        ERR_free_strings();
        EVP_cleanup();
}

/* return 0 on success */
int init_ssl()
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
#endif

        if(RAND_poll() == 0) {
                fprintf(stderr, "RAND_poll() failed.\n");
                return -1;
        }

        ssl_ctx = SSL_CTX_new(TLS_method());

	if (!ssl_ctx) {
                debug_msg("SSL_CTX_new filed: \n");
                ERR_print_errors_fp(stderr);
                return -1;
	}

        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv3);

        if (use_ssl) {
                if (certificate_chain_file && private_key_file) {

                        if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, certificate_chain_file) ||
                                !SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file, SSL_FILETYPE_PEM)) {
                                syslog(LOG_INFO, "TLS/SSL: Couldn't read %s or %s.\n", certificate_chain_file, private_key_file);
                                fprintf(stderr, "TLS/SSL: Couldn't read %s or %s.\n", certificate_chain_file, private_key_file);
                                free_ssl();
                                return -1;
                        }
                }

                else {
                        syslog(LOG_INFO, "TLS/SSL: will be generate private key and self-signed certificate in memory\n");
                        
                        if(!pkey || !x509) {
                                generate_cert_key();
                        }

                        if(!pkey || !x509) {
                                syslog(LOG_INFO, "TLS/SSL: Couldn't generate certificate or private key\n");
                                fprintf(stderr, "TLS/SSL: Couldn't generate certificate or private key\n");
                                free_ssl();
                                return -1;
                        }

                        if (!SSL_CTX_use_certificate(ssl_ctx, x509) ||
                                !SSL_CTX_use_PrivateKey(ssl_ctx, pkey)) {
                                syslog(LOG_INFO, "TLS/SSL: Something is wrong!\n");
                                fprintf(stderr, "TLS/SSL: Something is wrong!\n");
                                free_ssl();
                                return -1;
                        }
                }
        }
        return 0;
}

