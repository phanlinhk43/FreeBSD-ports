--- src/event/ngx_event_openssl.h.orig	2018-12-04 14:52:24 UTC
+++ src/event/ngx_event_openssl.h
@@ -159,7 +159,7 @@ ngx_int_t ngx_ssl_certificate(ngx_conf_t
 ngx_int_t ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers,
     ngx_uint_t prefer_server_ciphers);
 ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
-    ngx_str_t *cert, ngx_int_t depth);
+    ngx_str_t *cert, ngx_int_t depth, ngx_uint_t prodtrack);
 ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
     ngx_str_t *cert, ngx_int_t depth);
 ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl);
