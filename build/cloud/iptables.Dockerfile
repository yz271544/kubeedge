FROM golang:1.14-alpine3.11 AS builder

ARG GO_LDFLAGS

RUN go env -w GO111MODULE=on
# source
RUN apk update && apk add gcc && \
    apk --no-cache add build-base linux-headers sqlite-dev binutils-gold &&\
    apk --no-cache add iptables

WORKDIR /go/src/github.com/kubeedge/kubeedge
COPY . .

RUN CGO_ENABLED=1 go build -v -o /usr/local/bin/cloudcore -ldflags "$GO_LDFLAGS -w -s" \
github.com/kubeedge/kubeedge/cloud/cmd/cloudcore


FROM alpine:3.11

RUN apk update && apk --no-cache add iptables

COPY --from=builder /usr/local/bin/cloudcore /usr/local/bin/cloudcore

ENTRYPOINT ["cloudcore"]
