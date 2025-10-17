FROM node:slim

WORKDIR /app

COPY . .

EXPOSE 3000

RUN apt update -y &&\
    apt install -y --no-install-recommends curl openssl &&\
    apt clean &&\
    rm -rf /var/lib/apt/lists/* &&\
    npm install 

CMD ["node", "index.js"]
