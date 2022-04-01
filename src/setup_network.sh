# sudo systemctl status rabbitmq-server

sudo apt install rabbitmq-server

sudo rabbitmqctl add_user 'rabtest' '9a55f70a841f18b97c3a7db939b7adc9e34a0f1d'

sudo rabbitmqctl set_permissions -p qa1 rabtest "^rabtest-.*" ".*" ".*"

sudo rabbitmqctl set_permissions -p qa1 rabtest ".*" ".*" ".*"

