EXE = webserver

all: $(EXE)

$(EXE): webserver.o
	g++ webserver.o -o $(EXE)

webserver.o: webserver.cpp
	g++ -c -g -pthread webserver.cpp 

clean:
	rm -f *.o $(EXE)
