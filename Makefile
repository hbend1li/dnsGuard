CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
SRC = dnsGuard.cpp
TARGET = dnsGuard

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

dist-clean: clean

.PHONY: all clean dist-clean
