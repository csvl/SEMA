build-toolchain:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.dev.yml build

build-web-app:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker buildx build --rm --cache-from sema-web-app:latest -t sema-web-app  -f sema_web_app/Dockerfile .

build-scdg:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker buildx build --rm --cache-from sema-scdg:latest -t sema-scdg -f sema_scdg/Dockerfile .

build-classifier:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker buildx build --rm --cache-from sema-classifier:latest -t sema-classifier -f sema_classifier/Dockerfile .

pull-scdg:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker pull manonoreins/sema-scdg:latest
	docker image tag manonoreins/sema-scdg:latest sema-scdg:latest
	docker rmi manonoreins/sema-scdg:latest

pull-classifier:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker pull manonoreins/sema-classifier:latest
	docker image tag manonoreins/sema-classifier:latest sema-classifier:latest
	docker rmi manonoreins/sema-classifier:latest

run-toolchain-dev:
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.dev.yml up

run-toolchain:
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.yml up

stop-toolchain:
	docker compose -f docker-compose.deploy.yml down
	
stop-toolchain-dev:
	docker compose -f docker-compose.deploy.dev.yml down
	

ARGS = *
save-scdg-runs:
	docker cp sema-scdg:sema-scdg/application/database/SCDG/runs/ $(ARGS)

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build-toolchain    Build the entire toolchain, SemaSCDG, SemaClassifier and the web app docker containers"
	@echo "  build-web-app      Build the web app docker container"
	@echo "  build-scdg         Build the SCDG docker container"
	@echo "  build-classifier   Build the classifier docker container"
	@echo "  pull-scdg          Pull the SCDG docker image from DockerHub"
	@echo "  pull-classifier    Pull the classifier docker image from DockerHub"
	@echo "  run-toolchain      Run the toolchain web interface"
	@echo "  stop-toolchain     Stop the toolchain web interface"
	@echo "  save-scdg-runs     Save SCDG runs on path specified by ARGS"
