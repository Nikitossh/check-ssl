FROM golang as base
LABEL maintainer="Nikita Shesterikov <nikita@dotin.us>"
WORKDIR /app

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

COPY go.mod ./
RUN go clean -modcache
RUN go mod download
COPY . .

RUN go get -v github.com/docker/docker
RUN go build -o ssl


### Certs
FROM alpine:latest as certs
RUN apk --update add ca-certificates

### Application
FROM scratch as app
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=base app/ssl /
# Expose port 8080 to the outside world
EXPOSE 10000

# Command to run the executable
CMD ["./ssl -rest"]
