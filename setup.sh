# /bin/bash

if [ -d "./build" ]
then
	echo "Build folder already exists."
else
	mkdir build
	
	echo "go build -o heph ../src/main.go" > build/build.sh
	chmod +x build/build.sh

	echo "Browse to ./build and run the build.sh file to build the binary."
fi
