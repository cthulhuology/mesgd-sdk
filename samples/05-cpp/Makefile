CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I../..
LDFLAGS  = -lssl -lcrypto -lboost_system -lpthread

# nlohmann/json is header-only; point to its location if not system-installed
# CXXFLAGS += -I/usr/local/include

.PHONY: all clean

all: sample

sample: sample.cc
	$(CXX) $(CXXFLAGS) -o sample sample.cc $(LDFLAGS)

clean:
	rm -f sample
