FROM golang:alpine as builder
WORKDIR /src
ADD . /src

# Install git
RUN apk add --no-cache git

# Build cert-gen executable
RUN cd /src && go build -o cert-gen

# Create final app container image
FROM alpine
WORKDIR /app
COPY --from=builder /src/cert-gen /app/
ENTRYPOINT ./cert-gen
