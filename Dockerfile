FROM python:3.8-alpine

ENV PYTHONUNBUFFERED 1
RUN apk update
RUN apk add musl-dev wget git build-base linux-headers g++ gcc libffi-dev openssl-dev cargo

#mysql client
RUN apk add --no-cache mariadb-connector-c-dev
RUN apk update && apk add mariadb-dev && pip3 install mysqlclient && apk del mariadb-dev

RUN apk add netcat-openbsd
# Numpy
RUN pip3 install cython
RUN ln -s /usr/include/locale.h /usr/include/xlocale.h
RUN pip3 install numpy==1.23.5

RUN mkdir /app
WORKDIR /app
RUN pip3 install --upgrade pip setuptools
RUN python3 -m pip install --upgrade Pillow
COPY ./req.txt /app/req.txt
RUN pip3 install -r req.txt
RUN apk add --no-cache libstdc++
RUN pip3 install pyopenssl --upgrade
RUN pip3 install redis
RUN apk del musl-dev wget git build-base linux-headers g++ gcc libffi-dev openssl-dev cargo
RUN wget https://go.dev/dl/go1.20.4.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go1.20.4.linux-amd64.tar.gz  && \
  cd ta-lib/ && \
  ./configure --prefix=/usr && \
  make && \
  make install \
ENV PATH=/usr/local/go/bin
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
COPY . /app
EXPOSE 5050
RUN chmod +x /app/start.sh
ENTRYPOINT ["./start.sh"]