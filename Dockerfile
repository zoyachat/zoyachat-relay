FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 9090 9091
CMD ["node", "relay-ws.mjs"]
