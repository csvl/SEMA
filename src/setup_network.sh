# SETUP broker for master node

# sudo systemctl status rabbitmq-server

# TODO better interface

sudo apt install rabbitmq-server

sudo rabbitmqctl add_user 'rabbitmq' '9a55f70a841f18b97c3a7db939b7adc9e34a0f1d'

sudo rabbitmqctl add_vhost qa1

sudo rabbitmqctl set_permissions -p qa1 rabbitmq "^rabbitmq-.*" ".*" ".*"

sudo rabbitmqctl set_permissions -p qa1 rabbitmq ".*" ".*" ".*"

