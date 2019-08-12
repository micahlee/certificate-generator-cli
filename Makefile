.PHONY: build push

build: Dockerfile
	docker build -t micahlee/cert-gen:latest -f Dockerfile .

push:
	docker push micahlee/cert-gen:latest

default: build
