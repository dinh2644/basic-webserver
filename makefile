EXE1 = webserver/webserver
EXE2 = proxyserver/proxyserver

OBJ1 = webserver/webserver.o
OBJ2 = proxyserver/proxyserver.o

SRC1 = webserver/webserver.cpp
SRC2 = proxyserver/proxyserver.cpp

all: $(EXE1) $(EXE2)

# Web server
$(EXE1): $(OBJ1)
	g++ $(OBJ1) -o $(EXE1)

webserver/webserver.o: $(SRC1)
	g++ -c -g $(SRC1) -o $(OBJ1)

# Proxy server
$(EXE2): $(OBJ2)
	g++ $(OBJ2) -o $(EXE2)

proxyserver/proxyserver.o: $(SRC2)
	g++ -c -g $(SRC2) -o $(OBJ2)

# Create necessary folders
webserver:
	mkdir -p webserver

proxyserver:
	mkdir -p proxyserver

clean:
	rm -f webserver/*.o webserver/webserver
	rm -f proxyserver/*.o proxyserver/proxyserver