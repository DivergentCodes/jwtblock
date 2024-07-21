# Control the Docker Compose example.

all: start

start:
	cd ../../; GOOS="linux" GOARCH="amd64" bash ./scripts/build.sh
	docker compose down
	docker compose up --build --force-recreate

stop:
	docker compose down
