python3 -m pip install .;
cp /penv-fix/angr/stack_pointer_tracker.py  /usr/local/lib/python3.8/dist-packages/angr/analyses/stack_pointer_tracker.py
cp /penv-fix/angr/threading.py              /usr/local/lib/python3.8/dist-packages/angr/exploration_techniques/threading.py
cp /penv-fix/angr/heap_base.py              /usr/local/lib/python3.8/dist-packages/angr/state_plugins/heap/heap_base.py
cp /penv-fix/angr/__init__.py               /usr/local/lib/python3.8/dist-packages/angr/storage/memory_mixins/__init__.py
cp /penv-fix/angr/calling_conventions.py    /usr/local/lib/python3.8/dist-packages/angr/calling_conventions.py

cp /penv-fix/HTMLTestRunner/runner.py    /usr/local/lib/python3.8/dist-packages/HTMLTestRunner/runner.py


cd src/SemaSCDG/
echo "Compiling C code:"
cd tests; make all; cd ..;
echo "Running Linux tests:"
python3 tests/tests/linux/linux_test.py > "/app/src/SemaSCDG/tests/reports/$(date +"%Y%m%d_%H%M%S")_test.log"



# echo "Cleaning up:"
# cd tests; make clean; cd ..;