 #####################################################################
 # Example MPI C Makefile.
 #####################################################################
 

SRC = ec
CC = g++-5.2.0

HEADERS = ec_ops.h uberzahl.h
OBJECTS = $(SRC).o ec_ops.o uberzahl.o

default: $(SRC)

%.o: %.cpp $(HEADERS)
	$(CC) -c $< -o $@

$(SRC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@

clean:
	-rm -f $(OBJECTS)
	-rm -f $(SRC)
	rm *.gcov
	rm *.gcda
	rm *.gcno

run: $(SRC)
	./${SRC}

# clean:
# 	rm ${SRC}
# 	rm *.gcov
# 	rm *.gcda
# 	rm *.gcno

# analyze:
# 	${CC} -fprofile-arcs -ftest-coverage ${SRC}.cpp ec_ops.cpp uberzahl.cpp -o ${SRC}
# 	./${SRC}
# 	gcov-5.2.0 ${SRC}.cpp
# 	rm ${SRC}