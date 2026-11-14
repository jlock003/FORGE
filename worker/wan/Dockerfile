FROM registry.runpod.net/wlsdml1114-wan-animate-runpod-hub-main-dockerfile:46791944f
USER root
RUN python -m pip install --no-cache-dir "cryptography>=43,<47" "requests>=2.31,<3"
RUN command -v ffmpeg >/dev/null || (apt-get update && apt-get install -y --no-install-recommends ffmpeg && rm -rf /var/lib/apt/lists/*)
COPY worker/wan/secure_handler.py /secure_handler.py
COPY worker/wan/private_entrypoint.sh /private_entrypoint.sh
RUN chmod 700 /private_entrypoint.sh && chmod 600 /secure_handler.py
WORKDIR /
ENV PYTHONUNBUFFERED=1
CMD ["/private_entrypoint.sh"]
