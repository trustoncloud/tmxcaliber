FROM debian:bullseye-slim

ARG DRAWIO_VERSION=22.1.11
ARG USERNAME=debian
ARG TARGETARCH

RUN apt-get update -y && \
    apt-get install -y desktop-file-utils xvfb libappindicator3-1 libnotify4 wget libgbm1 libasound2 cpp cpp-10 \
    libauthen-sasl-perl libclone-perl libdata-dump-perl libencode-locale-perl libfile-basedir-perl \
    libfile-desktopentry-perl libfile-listing-perl libfile-mimeinfo-perl libfont-afm-perl libgdbm-compat4 libgdbm6 \
    libhtml-form-perl libhtml-format-perl libhtml-parser-perl libhtml-tagset-perl libhtml-tree-perl \
    libhttp-cookies-perl libhttp-daemon-perl libhttp-date-perl libhttp-message-perl libhttp-negotiate-perl \
    libio-html-perl libio-socket-ssl-perl libio-stringy-perl libipc-system-simple-perl libisl23 liblua5.3-0 \
    liblwp-mediatypes-perl liblwp-protocol-https-perl libmailtools-perl libmpc3 libmpfr6 libnet-dbus-perl \
    libnet-http-perl libnet-smtp-ssl-perl libnet-ssleay-perl libnspr4 libnss3 libperl5.32 libsecret-1-0 \
    libsecret-common libtext-iconv-perl libtie-ixhash-perl libtimedate-perl libtry-tiny-perl liburi-perl \
    libvte-2.91-0 libvte-2.91-common libwww-perl libwww-robotrules-perl libx11-protocol-perl libxcb-shape0 libxft2 \
    libxml-parser-perl libxml-twig-perl libxml-xpathengine-perl libxss1 libxv1 libxxf86dga1 netbase perl \
    perl-modules-5.32 perl-openssl-defaults termit x11-utils x11-xserver-utils xdg-utils python3 python3-venv

RUN wget https://github.com/jgraph/drawio-desktop/releases/download/v${DRAWIO_VERSION}/drawio-${TARGETARCH}-${DRAWIO_VERSION}.deb && \
    dpkg -i drawio-${TARGETARCH}-${DRAWIO_VERSION}.deb && \
    apt-get -y -f install && \
    rm drawio-${TARGETARCH}-${DRAWIO_VERSION}.deb && \
    useradd -m -s /bin/bash ${USERNAME}

COPY --chown=debian:debian ./ /home/${USERNAME}/app/

WORKDIR /home/${USERNAME}/app/
USER ${USERNAME}

RUN python3 -m venv .venv/ && \
    . .venv/bin/activate && \
    pip install -r requirements.txt && \
    pip install . && \
    chmod +x ./startup.sh

ENTRYPOINT ["./startup.sh"]
