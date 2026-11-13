# 首次启动需要 keytool 生成签名证书，因此用 JDK 而非 JRE
FROM eclipse-temurin:17-jdk

# python3-pil：自定义图标需要按原资源尺寸重绘，缺了也能跑（降级为原图直写）
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pil \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py axml.py assets.py ./
COPY static/ static/
COPY tools/ tools/

# 证书与密码仅在容器首次启动时生成于 /app/tools，不写进镜像或源码仓库
ENV APK_TOOLS_DIR=/app/tools \
    APK_UBER_SIGNER=/app/tools/uber-apk-signer.jar \
    APK_KEYSTORE=/app/tools/release.keystore \
    APK_KEYSTORE_PASS_FILE=/app/tools/.keystore_pass \
    PORT=7860

EXPOSE 7860
CMD ["python3", "server.py"]
