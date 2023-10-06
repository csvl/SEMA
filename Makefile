install-local:
	echo "Readme for further information about the parameters"
	bash install.sh

build-light-sema:
	docker build  --rm -t sema -f Dockerfile.sema .

build-full-sema:
	docker build  --rm -t sema-init -f Dockerfile.sema .
	docker build  --rm -t sema-pypy -f Dockerfile.sema.pypy .
	docker build  --rm -t sema-pypy-cuda -f Dockerfile.sema.cuda --build-arg image=sema-pypy .
	docker build  --rm -t sema -f Dockerfile.sema.fl --build-arg image=sema-pypy-cuda .

build-cuda-sema:
	docker build  --rm -t sema-init -f Dockerfile.sema .
	docker build  --rm -t sema -f Dockerfile.sema.cuda --build-arg image=sema-init .

build-web-sema-pypy:
	docker build  --rm -t sema-init -f Dockerfile.sema .
	docker build  --rm -t sema-pypy -f Dockerfile.sema.pypy .
	#docker build  --rm -t sema -f Dockerfile.sema.cuda --build-arg image=sema-pypy . # -pypy-cuda
	docker build  --rm -t sema -f Dockerfile.sema.fl --build-arg image=sema-pypy .
	docker build  --rm -t sema-web -f Dockerfile.sema.webapp --build-arg image=sema .

build-toolchain:
	docker-compose -f SemaWebApp/docker-compose.deploy.yml build

build-web-app:
	docker build --rm -t sema-web-app  -f SemaWebApp/Dockerfile .

build-scdg:
	docker build --rm -t sema-scdg -f SemaSCDG/Dockerfile .			   

run-web-app-service:
	docker run \
		--rm \
		-v $(PWD)/SemaWebApp/:/sema-web-app \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-e DISPLAY=$(DISPLAY) \
		-p 5000:5000 \
		--net=micro_network \
		--name="sema-web-app" \
		-it sema-web-app python3 application/SemaServer.py

run-scdg-service:	
	docker run \
		--rm \
		-v $(PWD)/SemaSCDG/:/sema-scdg \
		-v $(PWD)/submodules/angr-utils:/sema-scdg/application/submodules/angr-utils \
		-v $(PWD)/submodules/bingraphvis:/sema-scdg/application/submodules/bingraphvis \
		-v $(PWD)/penv-fix/:/sema-scdg/application/penv-fix \
		-v $(PWD)/database/:/sema-scdg/application/database\
		-e DISPLAY=$(DISPLAY) \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-p 5001:5001 \
		--net=micro_network \
		--name="sema-scdg" \
		-it sema-scdg bash

run-scdg-test:	
	docker run \
		--rm -i\
		-v $(PWD)/SemaSCDG/:/sema-scdg \
		-v $(PWD)/submodules/angr-utils:/sema-scdg/application/submodules/angr-utils \
		-v $(PWD)/submodules/bingraphvis:/sema-scdg/application/submodules/bingraphvis \
		-v $(PWD)/penv-fix/:/sema-scdg/application/penv-fix \
		-v $(PWD)/database/:/sema-scdg/application/database\
		-e DISPLAY=$(DISPLAY) \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-p 5001:5001 \
		--net=micro_network\
		--name="sema-scdg" \
		sema-scdg python3 SCDGApp.py

run-toolchain:
	docker run \
		--rm -d -i\
		-v $(PWD)/SemaSCDG/:/sema-scdg \
		-v $(PWD)/submodules/angr-utils:/sema-scdg/application/submodules/angr-utils \
		-v $(PWD)/submodules/bingraphvis:/sema-scdg/application/submodules/bingraphvis \
		-v $(PWD)/penv-fix/:/sema-scdg/application/penv-fix \
		-v $(PWD)/database/:/sema-scdg/application/database\
		-e DISPLAY=$(DISPLAY) \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-p 5001:5001 \
		--net=micro_network \
		--name="sema-scdg" \
		sema-scdg python3 SCDGApp.py
	sleep 3
	docker run \
		--rm \
		-v $(PWD)/SemaWebApp/:/sema-web-app \
		-v $(PWD)/database/:/sema-web-app/application/database\
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-e DISPLAY=$(DISPLAY) \
		-p 5000:5000 \
		--net=micro_network \
		--name="sema-web-app"\
		-it sema-web-app python3 application/SemaServer.py

stop-all-containers:
	docker stop $$(docker ps -a -q)

ARGS = *
save-scdg-runs:
	sudo mv database/SCDG/runs/$(ARGS) database/SCDG/saved_runs/

clean-scdg-runs:
	sudo rm -r database/SCDG/runs/*

clean-scdg-saved-runs:
	sudo rm -r database/SCDG/saved_runs/*
				
clean-scdg-empty-directory:
	sudo rm -r -f SemaSCDG/application/submodules
	sudo rm -r -f SemaSCDG/application/penv-fix
	sudo rm -r -f SemaSCDG/application/database
	sudo rm -r -f SemaSCDG/application/logs

clean-docker:
	docker image prune
	docker image prune -a
	docker rmi $(docker images -a -q) 