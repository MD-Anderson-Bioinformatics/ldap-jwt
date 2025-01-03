FROM node:22.12.0-slim as base

ARG PORT=3000
ARG NODE_UID=1001
ARG NODE_USER=nodeuser

ENV LDAPJWT_BASE_DIR="/usr/src/app"

EXPOSE ${PORT}

WORKDIR ${LDAPJWT_BASE_DIR}

COPY app .

RUN useradd -l -u ${NODE_UID} -r ${NODE_USER} -M -d ${LDAPJWT_BASE_DIR} && \
    chown -R ${NODE_USER}:${NODE_USER} ${LDAPJWT_BASE_DIR}

CMD [ "./setconfig" ]

##
## Production image (no dev dependecies)
##
FROM base as prod

USER ${NODE_USER}

RUN npm install --omit=dev

##
## CI testing image
##
FROM base as ci

USER ${NODE_USER}

RUN npm install

CMD ["npm", "test"]

##
## Development image with a few niceties
##
FROM base as dev

RUN mkdir -p /etc/skel   && \
    printf 'PS1="\033[1;32m\u@ldap-jwt:\w/$\033[0m "\nalias ls="ls --color=auto"\nalias vi=vim\n' >> /etc/skel/.profile && \
    printf 'PS1="\033[1;32m\u@ldap-jwt:\w/$\033[0m "\nalias ls="ls --color=auto"\nalias vi=vim\n' >> /etc/skel/.bashrc && \
    printf "syntax on\n:set hlsearch\n:set ruler\n:set ts=2\n:set list\n:set listchars=tab:<>\ninoremap jj <ESC>" >> /etc/skel/.vimrc && \
    cp /etc/skel/.profile /root/  && \
    cp /etc/skel/.bashrc /root/  && \
    cp /etc/skel/.vimrc  /root/  && \
    cp /etc/skel/.profile ${LDAPJWT_BASE_DIR}  && \
    cp /etc/skel/.bashrc ${LDAPJWT_BASE_DIR} && \
    cp /etc/skel/.vimrc ${LDAPJWT_BASE_DIR} && \
    apt-get update -y && apt-get install -y tree vim

USER ${NODE_USER}

RUN npm install
