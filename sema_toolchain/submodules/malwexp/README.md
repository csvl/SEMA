# malwexp

This program makes the interface with the malwexp database for the research team of Axel Legay at UCLouvain.
This database holds the metadata of malwares used by the team, as well as the experiments conducted by the members using them.


## Database description

The database used by this program is a MongoDB no-sql document-based database.
Using an unstructured database permits to have unrestricted set of fields for each document.
The software ensures that a small set of fields are always present in the database.
Other fields can be added and queried at all time, giving great flexibility with new developments and usage of the database.
There are two type of documents in the database.

- malware

	These documents record metadata of malwares used by the team for experiments. The required fields are:

	* hashes: list of known hashes of the malware (md5, sha256, …)
	* date: estimated creation date of the malware
	* family: family the malware belongs to
	* type: type of the malware
	* platform: platform for which the malware is designed
	* source: entity where the malware was found
	* location: location where the malware can be retrieved for experiments

- experiment

	These documents record information about experiments conducted by the team on malwares. The required fields are:

	* authors: list of authors of the experiment
	* samples: list of hashes of malwares used in the experiment
	* date: date of the experiment
	* description: short description of the experiment

There are also two fields included in every document, and automatically generated (they should not be provided by the user):

- user: username of the user that created the document
- creation: date at which the document was created


## Commands description

This program provides a Command-Line Interface (CLI) to interact with the database. The main command only provides an helper option:

	$ malwexp -h

There are three subcommands, two for each document type and one to interface with an online database. They only provide an helper option:

	$ malwexp malware -h
	$ malwexp experiment -h
	$ malwexp bazaar -h

Each document type provide subcommands for available operations. Each command provide an helper option. For malwares, the available operations are:

- create:

	This command lets the user create one or more malware document in the database.

		$ malwexp malware create -h

	This command takes as arguments a list of files, containing each either a single JSON object describing a malware document, or a JSON list of such objects.

	For each -p option given, the user will be prompted to describe a malware document.

	All malware documents prompted and read from argument files will be inserted in the database.

	The user will be prompted to confirm the insertion, unless the -f option is given.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

- get:

	This command lets the user retrieve specific malware documents corresponding to a given hash from the database.

		$ malwexp malware get -h

	This command takes as argument the hash to search malware documents of.

	If only a single document is found on the database, a single malware document is outputed as a JSON object. If multiple documents are found, a JSON list of those objects is outputed instead.

	The result is written on the console, unless the option -o is given with a filename on which to write the result.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

- delete:

	This command lets the user delete specific malware documents corresponding to a given hash from the database.

		$ malwexp malware get -h

	This command takes as argument the hash to search malware documents to delete.

	The user will be prompted to confirm the deletion, unless the -f option is given.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

- search:

	This command lets the user search for malware documents from the database.

		$ malwexp malware search -h

	If no option is given, this command will output all malware documents from the database.

	For each -f option, the command will only output documents where the given field contains the given value.

	If the -c option is given, the command will only output documents that were created in the database on the given date.

	If the -d option is given, the command will only output documents with a date field corresponding to the given date.

	If the -b option is given, the command will only output documents with a date field before to the given date.

	If the -a option is given, the command will only output documents with a date field after to the given date.

	If multiple -f, -c, -d, -b or -a options are given, the command will output documents that match all filters if the --all option is given or the --any option is missing. If the --any option is given, the command will output documents that match at least one of all filters.

	If only a single document is found on the database, a single document is outputed as a JSON object. If multiple documents are found, a JSON list of those objects is outputed instead.

	The result is written on the console, unless the option -o is given with a filename on which to write the result.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

- batch-update:

	This command lets the user modify a given field to a given value for all documents corresponding to given hashes.

		$ malwexp malware batch-update -h

	This command takes as arguments first a list of hashes to search malware documents to update. Then the command takes as argument the field to change and the value to set for this field.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

For experiments, the available operations are:

- create:

	This command lets the user create one or more experiment document in the database.

		$ malwexp experiment create -h

	This command takes as arguments a list of files, containing each either a single JSON object describing an experiment document, or a JSON list of such objects.

	For each -p option given, the user will be prompted to describe an experiment document.

	All experiment documents prompted and read from argument files will be inserted in the database.

	The user will be prompted to confirm the insertion, unless the -f option is given.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

- search:

	This command lets the user search for experiment documents from the database.

		$ malwexp experiment search -h

	If no option is given, this command will output all experiment documents from the database.

	For each -f option, the command will only output documents where the given field contains the given value.

	If the -c option is given, the command will only output documents that were created in the database on the given date.

	If the -d option is given, the command will only output documents with a date field corresponding to the given date.

	If the -b option is given, the command will only output documents with a date field before to the given date.

	If the -a option is given, the command will only output documents with a date field after to the given date.

	If multiple -f, -c, -d, -b or -a options are given, the command will output documents that match all filters if the --all option is given or the --any option is missing. If the --any option is given, the command will output documents that match at least one of all filters.

	If only a single document is found on the database, a single document is outputed as a JSON object. If multiple documents are found, a JSON list of those objects is outputed instead.

	The result is written on the console, unless the option -o is given with a filename on which to write the result.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

The last subcommand lets the user interact with the online database https://bazaar.abuse.ch. The available operations are:

- download:

	This command lets the user download the executable for a malware corresponding to a given sha256 hash from the online database.

		$ malwexp bazaar download -h

	This command takes as argument the sha256 hash of the malware to download, and a directory in which the downloaded executable will be placed.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

- get:

	This command lets the user retrieve specific malware documents corresponding to a given hash from the online database.

		$ malwexp bazaar get -h

	This command takes as argument the hash to search malware documents of.

	If only a single document is found on the online database, a single malware document is outputed as a JSON object. If multiple documents are found, a JSON list of those objects is outputed instead. The format of the document corresponds to the internal database.

	The result is written on the console, unless the option -o is given with a filename on which to write the result.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

- search:

	This command lets the user search for recent malware documents corresponding to a given malware family from the online database.

		$ malwexp bazaar search -h

	This command takes as argument the malware family to search malware documents of.

	Only the 100 latest documents will be outputed, unless the -l option is given with the number of documents to output with a maximum of 1000.

	If only a single document is found on the online database, a single malware document is outputed as a JSON object. If multiple documents are found, a JSON list of those objects is outputed instead. The format of the document corresponds to the internal database.

	The result is written on the console, unless the option -o is given with a filename on which to write the result.

	Some text will be printed to explain to the user what is happening during the command execution, unless the -q option is given.

## Requirements

A MongoDB database must be running in localhost, accessible by this user and on the default port.

A python interpreter must be installed on the machine, with at least version 3.6, and in the location /usr/local/bin/python3.

All python packages described in the file requirements.txt must be installed. This can be done with:

	/usr/local/bin/python3 -m pip install -r requirements.txt
