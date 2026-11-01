FROM eclipse-temurin:17-jre

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py axml.py ./
COPY tools/ tools/

ENV APK_TOOLS_DIR=/app/tools \
    APK_UBER_SIGNER=/app/tools/uber-apk-signer.jar \
    APK_KEYSTORE=/app/tools/release.keystore \
    PORT=7860

EXPOSE 7860
CMD ["python3", "server.py"]
