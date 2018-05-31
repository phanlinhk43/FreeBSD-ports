--- src/mail/ngx_mail_ssl_module.c.orig	2018-05-27 04:45:45 UTC
+++ src/mail/ngx_mail_ssl_module.c
@@ -403,7 +403,7 @@ ngx_mail_ssl_merge_conf(ngx_conf_t *cf, 
 
         if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                        &conf->client_certificate,
-                                       conf->verify_depth)
+                                       conf->verify_depth, conf->verify)
             != NGX_OK)
         {
             return NGX_CONF_ERROR;
