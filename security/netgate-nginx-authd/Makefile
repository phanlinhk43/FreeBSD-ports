# $FreeBSD$

PORTNAME=	nginx-authd
DISTVERSION=	20180630
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
GL_COMMIT=	0eb8132ce42ce5acf4e8881687ee3ad703e54549
FETCH_BEFORE_ARGS=	--no-verify-peer
BUILD_WRKSRC=	${WRKSRC}/${PORTNAME}
INSTALL_WRKSRC=	${WRKSRC}/${PORTNAME}

.include <bsd.port.mk>
