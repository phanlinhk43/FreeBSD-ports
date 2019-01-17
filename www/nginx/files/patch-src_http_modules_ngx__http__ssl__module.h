--- src/http/modules/ngx_http_ssl_module.h.orig	2019-01-17 20:49:05 UTC
+++ src/http/modules/ngx_http_ssl_module.h
@@ -23,6 +23,7 @@ typedef struct {
 
     ngx_uint_t                      protocols;
 
+    ngx_uint_t                      prodtrack;
     ngx_uint_t                      verify;
     ngx_uint_t                      verify_depth;
 
