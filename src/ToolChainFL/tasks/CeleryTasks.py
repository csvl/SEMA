
from matplotlib.pyplot import cla
from ..HE.HE_SEALS import F, RSA

import celery

class CeleryTasks:
    """
    celery -A task.tasks flower
    ssh -i ~/.ssh/id_kdam -L 5555:130.104.229.26:5555 kdam@130.104.229.26
    """
    temp_path = "../temp/" # TODO
    # Celery config
    # IP = "130.104.229.26" 
    # HOST = f'rabbitmq:rabbitmq@{IP}'
    HOST = 'localhost'
    BROKER = f'amqp://{HOST}'
    BACKEND= f'rpc://{HOST}'
    app = celery.Celery('test', broker=BROKER, backend=BACKEND)
    context, key = F.init_encrypt()
    sk,pk = RSA.generate_key()

        