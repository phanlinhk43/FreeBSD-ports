# $FreeBSD$

PORTNAME=	nginx-authd
DISTVERSION=	20190927
CATEGORIES=	security
PKGNAMEPREFIX=	netgate-

MAINTAINER=	garga@FreeBSD.org
COMMENT=	Netgate thoth nginx authentication daemon

LIB_DEPENDS=	libcryptoauth.so:security/netgate-cryptoauthlib \
		libthoth.so:security/netgate-libthoth \
		libucl.so:textproc/libucl \
		libevent.so:devel/libevent

USES=		ssl
USE_RC_SUBR=	netgate_nginx_authd
PLIST_FILES=	${PREFIX}/bin/nginx-authd
USE_LDCONFIG=	yes
USE_GITLAB=	yes
GL_SITE=	https://gitlab.netgate.com
GL_ACCOUNT=	thoth
GL_PROJECT=	thoth
GL_COMMIT=	45f8fb68474a0fde74b3e22a38ebbb097a09d586
FETCH_BEFORE_ARGS=	--no-verify-peer
BUILD_WRKSRC=	${WRKSRC}/${PORTNAME}
INSTALL_WRKSRC=	${WRKSRC}/${PORTNAME}

.include <bsd.port.mk>
