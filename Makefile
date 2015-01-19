all: install run

run:
	cat mycert.pem
	cat mykey.pem
	./client
install: 
	g++ -Wall ssl-b01705031client.cpp  -lpthread -o client -lssl -lcrypto
clean:
	rm client