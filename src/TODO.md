# General TODO 

* replace ToolChain by SEMA

* modify args parser split per tools  !!!

* set fixed version of submodule

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

# FL TODO 

* Add other classifier

* replace celery

* decentralized version

* Put same test data in each 