# Control the AWS Lambda Authorizor example.

all: build deploy

build:
	cd ../../; GOOS="linux" GOARCH="amd64" bash ./scripts/build.sh

deploy:
	cp "../../dist/jwtblock_linux_amd64_v1/jwtblock" bootstrap
	terraform apply

stop:
	echo "not implemented"
