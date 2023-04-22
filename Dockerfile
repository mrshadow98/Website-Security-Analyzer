FROM python:3.8-alpine

ENV PYTHONUNBUFFERED 1
RUN apk update
RUN apk add musl-dev wget git build-base linux-headers g++ gcc libffi-dev openssl-dev cargo

#mysql client
RUN apk add --no-cache mariadb-connector-c-dev
RUN apk update && apk add mariadb-dev && pip3 install mysqlclient && apk del mariadb-dev

RUN apk add netcat-openbsd

RUN mkdir /app
WORKDIR /app
RUN pip3 install --upgrade pip setuptools
RUN python3 -m pip install --upgrade Pillow
COPY ./req.txt /app/req.txt
RUN pip3 install -r req.txt
RUN apk add --no-cache libstdc++
RUN pip3 install pyopenssl --upgrade
RUN pip3 install redis
RUN pip3 install stripe==5.0.0
RUN pip3 install razorpay==1.3.0
RUN apk del musl-dev wget git build-base linux-headers g++ gcc libffi-dev openssl-dev cargo
COPY . /app
EXPOSE 5050
RUN chmod +x /app/start.sh
ENTRYPOINT ["./start.sh"]