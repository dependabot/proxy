.PHONY: build
build:
	go build .

.PHONY: run
run: build
	./dependabot-proxy

.PHONY: docker-build
docker-build:
	docker build -t dependabot/proxy .
