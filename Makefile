build-toolchain:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.yml build

build-web-app:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker buildx build --rm --cache-from sema-web-app:latest -t sema-web-app  -f sema_web_app/Dockerfile .

build-scdg:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker buildx build --rm --cache-from sema-scdg:latest -t sema-scdg -f sema_scdg/Dockerfile .

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

build-classifier:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker buildx build --rm --cache-from sema-classifier:latest -t sema-classifier -f sema_classifier/Dockerfile .

run-toolchain:
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.yml up

stop-toolchain:
	docker compose -f docker-compose.deploy.yml down

ARGS = *
save-scdg-runs:
	docker cp sema-scdg:sema-scdg/application/database/SCDG/runs/ $(ARGS)
