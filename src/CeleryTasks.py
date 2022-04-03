
try:
    from .HE.HE_SEALS import F, RSA
except:
    from HE.HE_SEALS import F, RSA

import celery

temp_path = "../temp/" # TODO

# Celery config
# Client: 130.104.229.26
# Client: 130.104.229.85
IP = "130.104.229.84/qa1"  # Master node
HOST = f'rabbitmq:9a55f70a841f18b97c3a7db939b7adc9e34a0f1d@{IP}'

# HOST = 'localhost'

BROKER = f'amqp://{HOST}'
BACKEND= f'rpc://{HOST}'

app = celery.Celery('ToolChainFL', broker=BROKER, backend=BACKEND)

context, key = F.init_encrypt()
sk,pk = RSA.generate_key()

"""
celery -A task.tasks flower
ssh -i ~/.ssh/id_kdam -L 5555:130.104.229.26:5555 kdam@130.104.229.26
"""
        