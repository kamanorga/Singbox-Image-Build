FROM node:alpine3.20

WORKDIR /tmp

COPY . .

EXPOSE 3000/tcp

RUN apk update && apk upgrade &&\
    apk add --no-cache openssl openssl-dev curl gcompat iproute2 coreutils bash &&\
    chmod +x index.js &&\
    npm install

CMD ["node", "index.js"]
