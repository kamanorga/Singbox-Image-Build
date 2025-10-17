FROM node:alpine3.20

WORKDIR /app

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

# 复制 package.json 和 package-lock.json
COPY package*.json ./

# 安装 Node.js 依赖
RUN npm ci --only=production || npm install --only=production

# 复制所有文件（node_modules 会被 .dockerignore 排除）
COPY . .

# 授权执行权限
RUN chmod +x index.js

# 暴露端口
EXPOSE 3000/tcp

# 启动应用
CMD ["node", "index.js"]
