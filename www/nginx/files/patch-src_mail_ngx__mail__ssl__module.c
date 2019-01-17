--- src/mail/ngx_mail_ssl_module.c.orig	2018-12-04 14:52:24 UTC
+++ src/mail/ngx_mail_ssl_module.c
@@ -404,7 +404,7 @@ ngx_mail_ssl_merge_conf(ngx_conf_t *cf, 
 
         if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                        &conf->client_certificate,
-                                       conf->verify_depth)
+                                       conf->verify_depth, 0)
             != NGX_OK)
         {
             return NGX_CONF_ERROR;
