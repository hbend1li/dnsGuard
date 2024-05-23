CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
SRC = dnsGuard.cpp
TARGET = dnsGuard
PREFIX = /usr/local

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

install: $(TARGET)
	install -d $(PREFIX)/etc/dnsGuard
	install -m 0755 $(TARGET) $(PREFIX)/etc/dnsGuard

clean:
	rm -f $(TARGET)

dist-clean: clean

.PHONY: all clean dist-clean install