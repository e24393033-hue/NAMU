FROM node:24-bookworm-slim
ENV NODE_ENV=production NAMU_HOST=0.0.0.0 NAMU_PORT=4173 NAMU_DATA_DIR=/data
WORKDIR /app
COPY --chown=node:node . /app
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 4173
CMD ["node", "server.js"]
