#!/bin/bash

distance=100

while [ $distance -lt 1000 ]; do
    ./threshold -m TwoRayGround -r $distance >>tmp.txt
    let distance=distance+50
done

gawk -f ./reduce.awk tmp.txt >> result.txt

rm tmp.txt
