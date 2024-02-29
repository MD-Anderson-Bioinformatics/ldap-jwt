FROM node:20.11.1-slim as base

ARG PORT=3000

ENV LDAPJWT_BASE_DIR="/usr/src/app"

EXPOSE ${PORT}

WORKDIR ${LDAPJWT_BASE_DIR}

COPY app .

CMD [ "./setconfig" ]

##
## Production image (no dev dependecies)
##
FROM base as prod

RUN npm install --omit=dev

##
## Development image with a few niceties
##
FROM base as dev

RUN npm install

RUN mkdir -p /etc/skel   && \
    printf 'PS1="\033[1;32m\u@ldap-jwt:\w/$\033[0m "\nalias ls="ls --color=auto"\nalias vi=vim\n' >> /etc/skel/.profile && \
    printf 'PS1="\033[1;32m\u@ldap-jwt:\w/$\033[0m "\nalias ls="ls --color=auto"\nalias vi=vim\n' >> /etc/skel/.bashrc && \
    printf "syntax on\n:set hlsearch\n:set ruler\n:set ts=2\n:set list\n:set listchars=tab:<>\ninoremap jj <ESC>" >> /etc/skel/.vimrc && \
    cp /etc/skel/.profile /root/  && \
    cp /etc/skel/.bashrc /root/  && \
    cp /etc/skel/.vimrc  /root/  && \
    apt-get update -y && apt-get install -y tree vim

