FROM node:20.11.1-slim

ENV LDAPJWT_BASE_DIR="/usr/src/app"
EXPOSE 3000

WORKDIR "${LDAPJWT_BASE_DIR}"

# Load dependencies to optimize the build cache
COPY package.json ./
RUN npm install

#Copy code
COPY . ./

CMD [ "./setconfig" ]
