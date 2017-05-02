# Example Docker Usage:
#   docker build -t ldap-jwt .
#   docker run -p 3000:3000 --rm -it --env-file config.txt ldap-jwt

FROM node:7.9.0

ENV LDAPJWT_BASE_DIR="/usr/src/app"
EXPOSE 3000

WORKDIR "${LDAPJWT_BASE_DIR}"

# Load dependencies to optimize the build cache
COPY package.json ./
RUN npm install

#Copy code
COPY . ./

CMD [ "./setconfig" ]
