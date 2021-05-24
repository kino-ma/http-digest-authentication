FROM golang:latest

WORKDIR /go/src

COPY ./go.* /go/src

RUN go install
CMD go run main.go
