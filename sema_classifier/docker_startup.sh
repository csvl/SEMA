#!/bin/bash
CONTAINER_ALREADY_STARTED="submodules/SEMA-quickspan/build"
if [ ! -e $CONTAINER_ALREADY_STARTED ]; then
    echo "-- First container startup --"
    cd submodules/SEMA-quickspan; mkdir build && cd build; cmake ..; make; 
    cd ..; cd ..; cd ..
else
    echo "-- Not first container startup --"
fi
if [ $1 -eq 1 ]; then
    bash
else
    python3 ./ClassifierApp.py
fi