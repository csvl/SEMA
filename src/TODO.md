# General TODO 

* replace ToolChain by SEMA

* modify args parser split per tools  !!!

* stop execution if memoery limite reach

* set fixed version of submodule

* Rajouter Jnkins

* Cleanup & improve installer

    * multiple os and python version support

* Testing

    * + de pre/post of functions

    * unittest/hypothesis

    * toy examples

* packed the project in binaries

* push project on `pypi`

* Benchmarking module/Response quality

* better pypy integration

* async logging for low latency

    * https://logbook.readthedocs.io/en/stable/

    * https://pypi.org/project/Logbook/

    * https://logbook.readthedocs.io/en/stable/api/queues.html#logbook.queues.ZeroMQSubscriber

    * https://stackoverflow.com/questions/24791395/python-logging-causing-latencies

    ```
    log_que = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(log_que)
    log_handler = logging.StreamHandler()
    queue_listener = logging.handlers.QueueListener(log_que, log_handler)
    queue_listener.start()
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s  %(message)s", handlers=[queue_handler])
    ```

#### Generate executable

https://pyinstaller.readthedocs.io/en/stable/requirements.html

TODO

```bash
pyinstaller -F -w --path="src/:penv/lib/python3.8/site-packages" --onefile src/ToolChain.py
```

#### Generate package

TODO better setup.py

https://test.pypi.org/account/register/

```bash
python3 -m pip install --upgrade build
python3 -m build
twine upload --repository testpypi dist/*
```


# FL TODO 

* Add other classifier

* replace celery

* decentralized version

* Put same test data in each 

