--- src/event/ngx_event_openssl.c.orig	2018-12-04 14:52:24 UTC
+++ src/event/ngx_event_openssl.c
@@ -9,6 +9,9 @@
 #include <ngx_core.h>
 #include <ngx_event.h>
 
+#include <syslog.h>
+#include <unistd.h>
+
 
 #define NGX_SSL_PASSWORD_BUFFER_SIZE  4096
 
@@ -20,6 +23,7 @@ typedef struct {
 
 static int ngx_ssl_password_callback(char *buf, int size, int rwflag,
     void *userdata);
+static int ngx_ssl_verify_prodtrack_callback(int ok, X509_STORE_CTX *x509_store);
 static int ngx_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store);
 static void ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where,
     int ret);
@@ -665,11 +669,14 @@ ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_
 
 ngx_int_t
 ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
-    ngx_int_t depth)
+    ngx_int_t depth, ngx_uint_t prodtrack)
 {
     STACK_OF(X509_NAME)  *list;
 
-    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_callback);
+    if (prodtrack == 1)
+        SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_prodtrack_callback);
+    else
+        SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_callback);
 
     SSL_CTX_set_verify_depth(ssl->ctx, depth);
 
@@ -797,6 +804,122 @@ ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *s
 }
 
 
+#define	NETGATE_CA_ISSUER	"/C=US/ST=Texas/L=Austin/O=Rubicon Communications, LLC (Netgate)/CN=ca-auth.netgate.com"
+#define	SERIAL_LENGTH			17
+#define	PRODTRACK_DEVICE_PROVISIONED	(1 << 0)
+#define	PRODTRACK_DEVICE_REGISTERED	(1 << 1)
+#define	PRODTRACK_DEVICE_TIMEOUT	(1 << 2)
+#define	PRODTRACK_DEVICE_SUSPENDED	(1 << 3)
+
+static int
+check_serial(char *serial)
+{
+
+    if (memcmp(serial, "123", 3) != 0)
+        return (-1);
+    if (memcmp(serial + 15, "ee", 2) != 0)
+        return (-1);
+    return (0);
+}
+
+static int
+prodtrack_get_status(char *serial, uint64_t *status)
+{
+    int err, s;
+    ssize_t len;
+    struct addrinfo hints, *res;
+
+    *status = 0;
+
+    /* Make hints. */
+    memset(&hints, 0, sizeof(hints));
+    hints.ai_family = PF_UNSPEC;
+    hints.ai_socktype = SOCK_STREAM;
+    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
+
+    /* Get the host address information. */
+    err = getaddrinfo("127.0.0.1", "4001", &hints, &res);
+    if (err != 0 || res == NULL)
+        return (-1);
+
+    s = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC,
+        res->ai_protocol);
+    if (s == -1)
+        return (-1);
+    if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
+        close(s);
+        return (-1);
+    }
+    len = write(s, serial, SERIAL_LENGTH);
+    if (len != SERIAL_LENGTH) {
+        close(s);
+        return (-1);
+    }
+    len = read(s, status, sizeof(*status));
+    if (len != sizeof(*status)) {
+        close(s);
+        return (-1);
+    }
+    close(s);
+    return (1);
+}
+
+static int
+ngx_ssl_verify_prodtrack_callback(int ok, X509_STORE_CTX *x509_store)
+{
+    X509              *cert;
+    X509_NAME         *sname, *iname;
+    char              *subject, *issuer, serial[20];
+    int                err;
+    uint64_t           status;
+
+    cert = X509_STORE_CTX_get_current_cert(x509_store);
+    err = X509_STORE_CTX_get_error(x509_store);
+
+    if (err != 0 || ok != 1)
+        return 0;
+
+    iname = X509_get_issuer_name(cert);
+    sname = X509_get_subject_name(cert);
+    if (iname == NULL || sname == NULL)
+        return 0;
+
+    issuer = X509_NAME_oneline(iname, NULL, 0);
+    if (strcmp(issuer, NETGATE_CA_ISSUER) == 0) {
+        OPENSSL_free(issuer);
+        return 1;
+    }
+
+    subject = X509_NAME_oneline(sname, NULL, 0);
+    if (strlen(subject) != 105) {
+        OPENSSL_free(subject);
+        OPENSSL_free(issuer);
+        return 0;
+    }
+    /* Check serial. */
+    memset(serial, 0, sizeof(serial));
+    memcpy(serial, subject + 84, SERIAL_LENGTH);
+    if (check_serial(serial) != 0) {
+        OPENSSL_free(subject);
+        OPENSSL_free(issuer);
+        return 0;
+    }
+    syslog(LOG_INFO, "%s: serial: %s subject: [%s] issuer: [%s]\n", __func__,
+        serial, subject, issuer);
+    OPENSSL_free(subject);
+    OPENSSL_free(issuer);
+
+    err = prodtrack_get_status(serial, &status);
+    syslog(LOG_INFO, "%s: err: %d status: %llu", __func__, err, status);
+    if (err != 1)
+        return 0;
+
+    if ((status & (PRODTRACK_DEVICE_TIMEOUT | PRODTRACK_DEVICE_SUSPENDED)) != 0)
+        return 0;
+
+    return 1;
+}
+
 static int
 ngx_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
 {
