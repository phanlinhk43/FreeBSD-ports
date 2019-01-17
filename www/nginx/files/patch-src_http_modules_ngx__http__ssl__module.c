--- src/http/modules/ngx_http_ssl_module.c.orig	2018-12-04 14:52:24 UTC
+++ src/http/modules/ngx_http_ssl_module.c
@@ -70,6 +70,12 @@ static ngx_conf_enum_t  ngx_http_ssl_ver
     { ngx_null_string, 0 }
 };
 
+static ngx_conf_enum_t  ngx_http_ssl_prodtrack_verify[] = {
+    { ngx_string("off"), 0 },
+    { ngx_string("on"), 1 },
+    { ngx_null_string, 0 }
+};
+
 
 static ngx_command_t  ngx_http_ssl_commands[] = {
 
@@ -143,6 +149,13 @@ static ngx_command_t  ngx_http_ssl_comma
       offsetof(ngx_http_ssl_srv_conf_t, verify),
       &ngx_http_ssl_verify },
 
+    { ngx_string("ssl_prodtrack_verify"),
+      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
+      ngx_conf_set_enum_slot,
+      NGX_HTTP_SRV_CONF_OFFSET,
+      offsetof(ngx_http_ssl_srv_conf_t, prodtrack),
+      &ngx_http_ssl_prodtrack_verify },
+
     { ngx_string("ssl_verify_depth"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_num_slot,
@@ -548,6 +561,7 @@ ngx_http_ssl_create_srv_conf(ngx_conf_t 
     sscf->enable = NGX_CONF_UNSET;
     sscf->prefer_server_ciphers = NGX_CONF_UNSET;
     sscf->buffer_size = NGX_CONF_UNSET_SIZE;
+    sscf->prodtrack = NGX_CONF_UNSET_UINT;
     sscf->verify = NGX_CONF_UNSET_UINT;
     sscf->verify_depth = NGX_CONF_UNSET_UINT;
     sscf->certificates = NGX_CONF_UNSET_PTR;
@@ -598,6 +612,7 @@ ngx_http_ssl_merge_srv_conf(ngx_conf_t *
 
     ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
     ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);
+    ngx_conf_merge_uint_value(conf->prodtrack, prev->prodtrack, 0);
 
     ngx_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
     ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
@@ -734,7 +749,7 @@ ngx_http_ssl_merge_srv_conf(ngx_conf_t *
 
         if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                        &conf->client_certificate,
-                                       conf->verify_depth)
+                                       conf->verify_depth, conf->prodtrack)
             != NGX_OK)
         {
             return NGX_CONF_ERROR;
