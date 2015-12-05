 #####################################################################
 # Example MPI C Makefile.
 #####################################################################
 
SRC = ec
CC = g++-5.2.0

default:
	${CC} ec.cpp ec_ops.cpp uberzahl.cpp -o ${SRC}
run:
	# ${CC} ec.cpp ec_ops.cpp uberzahl.cpp -o ${SRC}
	./${SRC}

test:
	./test.sh

clean:
	rm ${SRC}
	rm *.gcov
	rm *.gcda
	rm *.gcno

analyze:
	${CC} -fprofile-arcs -ftest-coverage ${SRC}.cpp ec_ops.cpp uberzahl.cpp -o ${SRC}
	./${SRC}
	gcov-5.2.0 ${SRC}.cpp
	rm ${SRC}