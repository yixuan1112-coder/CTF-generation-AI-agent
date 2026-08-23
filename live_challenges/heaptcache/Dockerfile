FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/* && useradd -m -u 10001 ctf
WORKDIR /app
COPY chall.c serve.py /app/
RUN gcc -no-pie -fno-stack-protector -w -o /app/chall /app/chall.c && chmod 755 /app/chall
ENV FLAG=flag{replace_at_deployment}
ENV PORT=9000
EXPOSE 9000
USER ctf
CMD ["python", "serve.py"]
