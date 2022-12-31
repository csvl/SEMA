install-local:
	echo "Readme for further information about the parameters"
	bash install.sh

build-light-sema:
	docker build -t sema -f Dockerfile.sema .

build-full-sema:
	docker build -t sema-init -f Dockerfile.sema .
	docker build -t sema-pypy -f Dockerfile.sema.pypy .
	docker build -t sema-pypy-cuda -f Dockerfile.sema.cuda --build-arg image=sema-pypy .
	docker build -t sema -f Dockerfile.sema.fl --build-arg image=sema-pypy-cuda .

build-cuda-sema:
	docker build -t sema-init -f Dockerfile.sema .
	docker build -t sema -f Dockerfile.sema.cuda --build-arg image=sema-init .

build-web-sema:
	docker build -t sema-init -f Dockerfile.sema .
	docker build -t sema-pypy -f Dockerfile.sema.pypy .
	#docker build -t sema -f Dockerfile.sema.cuda --build-arg image=sema-pypy . # -pypy-cuda
	docker build -t sema -f Dockerfile.sema.fl --build-arg image=sema-pypy .
	docker build -t sema-web -f Dockerfile.sema.webapp --build-arg image=sema .

run-web:
	#bash update_etc_hosts.sh
	docker run --privileged  \
			   -v $(PWD)/src/:/app/src/ \
			   -v $(PWD)/SemaWebApp/:/app/SemaWebApp/ \
			   -v /tmp/.X11-unix:/tmp/.X11-unix \
    		   -e DISPLAY=$(DISPLAY) \
			   -p 8080:80 \
			   --network="bridge" \
			   -it sema-web bash run_server.sh

run-sh:
	docker run --privileged  \
			   -v $(PWD)/src/:/app/src/ \
			   -v $(PWD)/SemaWebApp/:/app/SemaWebApp/ \
			   -v /tmp/.X11-unix:/tmp/.X11-unix \
    		   -e DISPLAY=$(DISPLAY) \
			   -p 8080:80 \
			   --network="bridge" \
			   -it sema-web bash
