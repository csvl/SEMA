mkdocs:
	python3 automate_mkdocs.py -
	gendocs --config mkgendocs.yml
	cp *.md docs/
	cp sema_toolchain/sema_scdg/README.md docs/sema_scdg.md
	cp sema_toolchain/sema_classifier/README.md docs/sema_classifier.md
	cp sema_toolchain/sema_web_app/README.md docs/sema_web_app.md
	cp README.md docs/home.md
	mkdocs build --verbose
	mkdocs serve 
