FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --production

COPY . .

RUN mkdir -p /app/data/files

EXPOSE 9100

ENV PORT=9100
ENV DB_PATH=/app/data/server.db
ENV FILE_UPLOAD_DIR=/app/data/files
ENV JWT_SECRET=change-this-in-production

CMD ["node", "index.js"]
