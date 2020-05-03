FROM python:3.8-alpine
ENV PYTHON_VERSION=3.8

WORKDIR /exporter
COPY requirements.txt ./

RUN apk --no-cache --update add --virtual build-dependencies build-base \
  && pip install -r requirements.txt \
  && apk del build-dependencies build-base \
  && rm -rf requirements.txt

COPY wallarm_api /usr/local/lib/python$PYTHON_VERSION/wallarm_api
COPY demo_export.py ./

CMD ["./demo_export.py"]
