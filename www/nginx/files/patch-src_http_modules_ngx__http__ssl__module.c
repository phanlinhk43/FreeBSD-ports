--- src/http/modules/ngx_http_ssl_module.c.orig	2018-05-27 04:46:47 UTC
+++ src/http/modules/ngx_http_ssl_module.c
@@ -66,6 +66,7 @@ static ngx_conf_enum_t  ngx_http_ssl_ver
     { ngx_string("on"), 1 },
     { ngx_string("optional"), 2 },
     { ngx_string("optional_no_ca"), 3 },
+    { ngx_string("prodtrack"), 4 },
     { ngx_null_string, 0 }
 };
 
@@ -729,7 +730,7 @@ ngx_http_ssl_merge_srv_conf(ngx_conf_t *
 
         if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                        &conf->client_certificate,
-                                       conf->verify_depth)
+                                       conf->verify_depth, conf->verify)
             != NGX_OK)
         {
             return NGX_CONF_ERROR;
