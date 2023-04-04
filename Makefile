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

build-web-sema:
	docker build  --rm -t sema-init -f Dockerfile.sema .
	#docker build  --rm  -t sema-pypy -f Dockerfile.sema.pypy .
	#docker build  --rm -t sema -f Dockerfile.sema.cuda --build-arg image=sema-pypy . # -pypy-cuda
	docker build  --rm -t sema -f Dockerfile.sema.fl --build-arg image=sema-init .
	docker build  --rm -t sema-web-nf -f Dockerfile.sema.webapp --build-arg image=sema .
	docker build  --rm -t sema-web -f Dockerfile.sema.fix --build-arg image=sema-web-nf .

run-web:
	#bash update_etc_hosts.sh
	docker run  \
			   --rm \
			   -v $(PWD)/src/:/app/src/ \
			   -v $(PWD)/setup.py:/app/setup.py \
			   -v $(PWD)/run_server.sh:/app/run_server.sh \
			   -v /app/src/submodules/ \
			   -v $(PWD)/SemaWebApp/:/app/SemaWebApp/ \
			   -v /tmp/.X11-unix:/tmp/.X11-unix \
			   -v $(PWD)/penv-fix/:/penv-fix/ \
    		   -e DISPLAY=$(DISPLAY) \
			   -p 80:80 \
			   --network="bridge" \
			   -it sema-web bash run_server.sh

run-sh:
	docker run \
			   --rm \
			   -v $(PWD)/src/:/app/src/ \
			   -v /app/src/submodules/ \
			   -v $(PWD)/SemaWebApp/:/app/SemaWebApp/ \
			   -v /tmp/.X11-unix:/tmp/.X11-unix \
    		   -e DISPLAY=$(DISPLAY) \
			   -p 80:80 \
			   --network="bridge" \
			   -it sema-web bash
