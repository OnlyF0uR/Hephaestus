# /bin/bash

mkdir -p build

echo "go build -o heph ../src/main.go" > build/build.sh
chmod +x build/build.sh
