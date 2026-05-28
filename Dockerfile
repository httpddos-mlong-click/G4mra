FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --ignore-scripts

COPY src/ ./src/
COPY public/ ./public/

RUN mkdir -p /app/data

ENV PORT=3000
ENV DATA_DIR=/app/data
ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "src/server.js"]
