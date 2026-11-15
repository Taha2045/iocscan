CXX = g++
CXXFLAGS = -std=c++17 -Wall -Iinclude

# الملفات اللي غادي نترجمو
SRCS = src/main.cpp src/scanner.cpp src/sha256.cpp

# اسم التطبيق اللي غادي يخرج
TARGET = iocscan

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)
