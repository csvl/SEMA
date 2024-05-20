## Pypi package update

* Have a pypi account and being an administrator of the project

* Update the version in `pyproject.toml`

* At the root of the project run :
    ```bash
    build with : python3 -m build
    upload with : twine upload dist/*
    ```

## Dockerhub upate

* Have a Dockerhub account and being a collaborator of the project

* Login on Dockerhub in the terminal using :
        ```
        docker login --username=yourhubusername --email=youremail@company.com
        ```

* Tag the image of sema-classifier or sema-scdg using this :
        ```
        docker tag DockerID manonoreins/sema-scdg:latest
        ```

* Push on Dockerhub by running :
        ```
        docker push manonoreins/sema-scdg:latest
        ```
