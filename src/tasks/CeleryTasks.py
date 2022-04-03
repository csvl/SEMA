
try:
    from .HE.HE_SEALS import F, RSA
except:
    from HE.HE_SEALS import F, RSA

import celery

temp_path = "../temp/" # TODO
# Celery config
IP = "130.104.229.84"  # Master node

# Client: 130.104.229.26
# Client: 130.104.229.85

HOST = f'rabbitmq:rabbitmq@{IP}'
# HOST = 'localhost'
BROKER = f'amqp://{HOST}'
BACKEND= f'rpc://{HOST}'
app = celery.Celery('ToolChainFL', broker=BROKER, backend=BACKEND)
context, key = F.init_encrypt()
sk,pk = RSA.generate_key()

    

        