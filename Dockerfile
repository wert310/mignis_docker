FROM alpine:3.9 as builder
RUN sed -i 's/v3.9/edge/g' /etc/apk/repositories
RUN apk update && apk add build-base go curl git \
        && git clone https://github.com/jpillora/webproc.git \
        && cd webproc \
        && go get . && go build .

FROM alpine:3.9
RUN apk add iptables python2 py2-pip
COPY --from=builder /webproc/webproc /bin/webproc
ADD . /mignis_docker
ADD ./example.conf /mignis.conf
WORKDIR /mignis_docker
RUN pip install -r requirements.txt
ENV HTTP_USER user
ENV HTTP_PASS pass
EXPOSE 9090
ENTRYPOINT ["webproc", "-p", "9090", "-c","/mignis.conf", "--","./mignis_docker.py","-c", "/mignis.conf", "-p", "-x"]
