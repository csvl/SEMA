#!/bin/bash

# for file in Examples/mirai_64/*
for file in Examples/Sample_paper/autoit/*
do
    python3 Build_SCDG.py $file --method=BFS --dir mirai64_gs/
done
