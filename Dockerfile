FROM node:alpine3.20

# 使用标准应用目录
WORKDIR /app

# 复制所有文件
COPY . .

# 暴露端口
EXPOSE 3000/tcp

# 安装系统依赖并清理缓存
RUN apk update && apk upgrade &&\
    apk add --no-cache \
        openssl \
        openssl-dev \
        curl \
        bash \
        gcompat \
        iproute2 \
        coreutils \
        grep \
        sed \
        gawk &&\
    chmod +x index.js &&\
    npm install --production &&\
    npm cache clean --force &&\
    apk del openssl-dev &&\
    rm -rf /var/cache/apk/* /tmp/*

# 启动应用
CMD ["npm", "start"]
