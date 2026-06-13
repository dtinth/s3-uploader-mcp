FROM denoland/deno:bin-2.6.7 AS bin

FROM debian:bookworm-slim
COPY --from=bin /deno /usr/local/bin/deno

WORKDIR /app
COPY . .

EXPOSE 8000

CMD ["deno", "run", "-A", "main.ts"]
