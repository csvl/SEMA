:page_with_curl: Sema web application (`SemaWebApp`)
====


This module contains a web application allowing to manage runs on SemaSCDG and SemaClassifier by entering parameters value on a graphical interface.
The web application is built with Flask and communicates with the docker containers of SemaSCDG and SemaClassifier via a REST API.

## How to use ?

First launch the containers :
```bash
make run-toolchain
```

This will start the SCDG, the classifier, and the web app services.
Wait for the containers to be up, then visit 127.0.0.1:5000 on your browser

For details on how SemaSCDG and SemaClassifier work, check their README :

* SCDG README : ![SCDG README](./sema_toolchain/sema_scdg/README.md)

* Classifier README : ![Classifier README](./sema_toolchain/sema_classifier/README.md)
