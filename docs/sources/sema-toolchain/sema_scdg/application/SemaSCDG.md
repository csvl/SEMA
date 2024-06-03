#


### __handle_exception
```python
.__handle_exception(
   e, sema_scdg, crashed_samples
)
```

---
Handles exceptions during the binary analysis process.

This function manages different types of exceptions, logs errors, ends the analysis run, and keeps track of crashed samples.

----


### __process_folder
```python
.__process_folder(
   folder, sema_scdg, crashed_samples
)
```

---
Processes files in a folder for building the System Call Dependency Graph (SCDG).

This function iterates through files in a folder, sets up the analysis environment for each file, runs the analysis, handles exceptions, and updates progress.

----


### start_scdg
```python
.start_scdg()
```

---
Starts the System Call Dependency Graph (SCDG) analysis process.

This function initiates the analysis by determining whether to analyze a single binary or multiple binaries in a folder, running the analysis, handling exceptions, and reporting any crashed samples.
