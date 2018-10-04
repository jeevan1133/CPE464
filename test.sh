#!/bin/bash

make clean
echo -e "cleaned files\n"

make
for x in *.pcap; do
	echo -e "\n******* Diffing without any 3rd argument***** \n"
	echo -e "****File opened is " $x "****\n"

	./trace-Linux-x86_64 $x > t.out
	./trace $x > t.exp
	diff t.out t.exp

	for i in {1..7}; do
		./trace-Linux-x86_64 $x $i > t$i.out
		thisecho=`echo $?`
		./trace $x $i > t$i.exp
		thatecho=`echo $?`

		if [ "$thisecho" -ne "$thatecho" ]; then
			echo -e "echo Codes don't match\n"
		fi;

		diff t$i.out t$i.exp > diff$i.diff

		if [ $? == 1 ]; then
			diff t$i.out t$i.exp > diff$i.diff
      else
         rm diff$i.diff 
		fi;

		rm t$i.out
		rm t$i.exp
	done
	rm t.out
	rm t.exp
done

