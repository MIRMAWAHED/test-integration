FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY examples ./examples
EXPOSE 8080
CMD ["node", "src/server.mjs"]
