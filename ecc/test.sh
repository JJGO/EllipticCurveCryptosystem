#!/bin/bash
for i in `seq 1 $1`;
	do
		A="$(jot -r 1  -10000000000000 10000000000000)"
		echo $A >> results.txt
		echo $A | ./ec | grep -E 'Correct|different' >> results.txt
	done