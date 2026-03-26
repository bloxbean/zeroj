FROM node:22-slim

WORKDIR /app

# Install snarkjs and express
COPY package.json ./
RUN npm install --production

# Copy server
COPY server.js ./

# Circuits directory (mount via volume)
RUN mkdir -p /circuits

ENV PORT=3000
ENV CIRCUITS_DIR=/circuits

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
