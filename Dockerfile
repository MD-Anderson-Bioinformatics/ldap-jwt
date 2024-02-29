FROM node:20.11.1-slim

ENV LDAPJWT_BASE_DIR="/usr/src/app"
EXPOSE 3000

WORKDIR "${LDAPJWT_BASE_DIR}"

COPY app .

RUN npm install

CMD [ "./setconfig" ]
