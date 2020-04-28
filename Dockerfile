FROM golang:1.12-alpine

ENV GO111MODULE=on
WORKDIR /app/server
COPY go.mod .
COPY go.sum .

RUN apk add git
RUN go mod download
COPY . .

RUN go build
CMD ["./statuscake-exporter"]
