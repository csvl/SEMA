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

build-classifier:
	docker network inspect micro_network >/dev/null 2>&1 || docker network create --driver bridge micro_network
	docker buildx build --rm --cache-from sema-classifier:latest -t sema-classifier -f sema_classifier/Dockerfile .

run-classifier-service:
	docker run \
		--rm \
		-v $(PWD)/sema_classifier/:/sema-classifier \
		-v $(PWD)/submodules/SEMA-quickspan:/sema-classifier/application/submodules/SEMA-quickspan \
		-v $(PWD)/submodules/bingraphvis:/sema-classifier/application/submodules/bingraphvis \
		-v $(PWD)/penv-fix/:/sema-classifier/application/penv-fix \
		-v $(PWD)/database/:/sema-classifier/application/database\
		-v $(PWD)/yara/:/sema-classifier/application/yara\
		-e DISPLAY=$(DISPLAY) \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-p 5002:5002 \
		--net=micro_network \
		--name="sema-classifier" \
		-it sema-classifier ../docker_startup.sh 1

run-scdg-service:
	docker run \
		--rm \
		-e DISPLAY=$(DISPLAY) \
		-p 5001:5001 \
		--net=micro_network \
		--name="sema-scdg" \
		-it sema-scdg bash

run-toolchain:
	DOCKER_BUILDKIT=0 docker compose -f docker-compose.deploy.yml up

stop-toolchain:
	docker compose -f docker-compose.deploy.yml down

ARGS = *
save-scdg-runs:
	docker cp sema-scdg:sema-scdg/application/database/SCDG/runs/ $(ARGS)
