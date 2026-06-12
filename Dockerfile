# MediaVault — self-hosted encrypted media vault
# Build:  docker build -t mediavault .
# Run:    docker run -p 4321:4321 -v mv_data:/app/data -v mv_uploads:/app/uploads mediavault

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=4321

COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./

# data/ holds the SQLite vault DB, uploads/ holds encrypted media —
# both must be volumes or your vault dies with the container.
RUN mkdir -p data uploads && chown -R node:node /app
USER node
VOLUME ["/app/data", "/app/uploads"]

EXPOSE 4321
CMD ["node", "--no-warnings", "./dist/server/entry.mjs"]
