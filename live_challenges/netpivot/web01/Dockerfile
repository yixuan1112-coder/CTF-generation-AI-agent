FROM python:3.12-slim
RUN useradd -m -u 10001 ctf
WORKDIR /app
COPY server.py /app/server.py
ENV PORT=9000
EXPOSE 9000
USER ctf
CMD ["python", "server.py"]
