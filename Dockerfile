FROM node:alpine3.20

WORKDIR /app

# 先复制 package.json 和 package-lock.json (如果存在)
COPY package*.json ./

# 安装系统依赖
RUN apk update && apk upgrade && \
    apk add --no-cache \
        openssl \
        curl \
        bash \
        gcompat \
        iproute2 \
        coreutils \
        grep \
        sed \
        gawk

# 安装 Node.js 依赖
RUN npm install --production

# 复制其他文件
COPY . .

# 授权执行权限
RUN chmod +x index.js

# 暴露端口
EXPOSE 3000/tcp

# 启动应用
CMD ["npm", "start"]
