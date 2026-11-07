FROM python:3.12-alpine
# iptables to add the blocking rule on the target's network
RUN apk add --no-cache iptables
COPY responder.py /responder.py
CMD ["python3", "-u", "/responder.py"]
