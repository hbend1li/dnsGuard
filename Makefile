CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
SRC = dnsGuard.cpp
TARGET = dnsGuard
PREFIX = /usr/local
DNSGUARD_DIR = /etc/dnsGuard
DNSMASQ_DIR = /etc/dnsmasq.d
HTTPD_DIR = $(DNSGUARD_DIR)/httpd
RULES_DIR = $(DNSGUARD_DIR)/rules
USER = $(shell whoami)
GROUP = $(shell id -gn)

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

install: $(TARGET)
	# Create necessary directories
	install -d $(DNSGUARD_DIR)
	install -d $(DNSMASQ_DIR)
	install -d $(HTTPD_DIR)
	install -d $(RULES_DIR)
	
	# Install the binary
	install -m 0755 $(TARGET) $(DNSGUARD_DIR)
	
	# Create symlink if it doesn't exist
	test -L $(RULES_DIR) || ln -sf $(DNSMASQ_DIR) $(RULES_DIR)
	
	# Set permissions to allow non-root execution
	chown -R $(USER):$(GROUP) $(DNSGUARD_DIR)
	chmod -R 755 $(DNSGUARD_DIR)
	
	# Set special permissions for the binary
	chmod u+s $(DNSGUARD_DIR)/$(TARGET)
	
	# Check for required packages
	@which git >/dev/null || (echo "Error: git is not installed" && exit 1)
	@which dnsmasq >/dev/null || (echo "Error: dnsmasq is not installed" && exit 1)
	@which busybox >/dev/null || (echo "Error: busybox is not installed" && exit 1)

uninstall:
	rm -rf $(DNSGUARD_DIR)/$(TARGET)
	rm -rf $(HTTPD_DIR)
	rm -rf $(RULES_DIR)
	pkill -f "busybox httpd -p.*65321" || true

clean:
	rm -f $(TARGET)

dist-clean: clean

.PHONY: all clean dist-clean install uninstall