# $FreeBSD$

PORTNAME=	ping-authd
DISTVERSION=	20190415
CATEGORIES=	security
PKGNAMEPREFIX=	netgate-

MAINTAINER=	garga@FreeBSD.org
COMMENT=	Netgate Thoth ping authentication daemon

LIB_DEPENDS=	libcryptoauth.so:security/netgate-cryptoauthlib \
		libthoth.so:security/netgate-libthoth \
		libucl.so:textproc/libucl \
		libevent.so:devel/libevent \
		libfcgi.so:www/fcgi

RUN_DEPENDS=	${LOCALBASE}/bin/setuidgid:sysutils/daemontools

USERS?=		pingauth
GROUPS?=	pingauth

USES=		ssl
USE_RC_SUBR=	netgate_ping_authd
PLIST_FILES=	${PREFIX}/bin/ping-authd
USE_LDCONFIG=	yes
USE_GITLAB=	yes
GL_SITE=	https://gitlab.netgate.com
GL_ACCOUNT=	thoth
GL_PROJECT=	thoth
GL_COMMIT=	b0c03466ccd5f6e70d1b4d9186d4650cd5bcd7da
FETCH_BEFORE_ARGS=	--no-verify-peer
BUILD_WRKSRC=	${WRKSRC}/${PORTNAME}
INSTALL_WRKSRC=	${WRKSRC}/${PORTNAME}

.include <bsd.port.mk>
