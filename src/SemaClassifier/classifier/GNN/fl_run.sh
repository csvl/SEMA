#!/bin/bash
declare -i nclients="2"
declare -i nrounds="3"

echo "Starting server"
python ./SemaClassifier/classifier/GNN/FL_server.py --nclients=${nclients}&
sleep 3  # Sleep for 3s to give the server enough time to start



for ((i=0; i<nclients; i++)); do
    echo "Starting client $i"
    python ./SemaClassifier/classifier/GNN/fl_gnn.py --nclients=${nclients} --partition=${i}&
done

python ./SemaClassifier/classifier/GNN/GNN_script.py --nclients=${nclients} &

# This will allow you to use CTRL+C to stop all background processes
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM
# Wait for all background processes to complete
wait