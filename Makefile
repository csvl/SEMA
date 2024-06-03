gen-docs:
	python3 ./doc/generate_doc.py
	gendocs --config doc/mkgendocs.yaml

mkdocs:
	make gen-docs
	mkdocs serve