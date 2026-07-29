# VULN (Security Misconfiguration): no multi-stage hardening, runs as root,
# base image tag not pinned to digest — intentional for benchmark realism.
FROM golang:1.20

WORKDIR /app
COPY go.mod ./
COPY . .

RUN go mod tidy && go build -o vulnbank .

ENV APP_DEBUG=true
EXPOSE 8080

CMD ["./vulnbank"]
