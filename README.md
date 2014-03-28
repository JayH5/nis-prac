nis-prac
========

Network and Inter-network Security 2014 Practical

## Requirements
* Java 7 or greater is required to run (Java 6 will not work).
* The build scripts require a UNIX-like terminal to run.

## Instructions
Shell scripts are provided to build and clean as well as run the server and client.

To compile the source code, run ./build.sh
To start the server, run ./server.sh
To run the test sequence with the client, run ./client.sh
To remove all compiled .class files, run ./clean.sh

## File structure:
* Client files are stored in a folder named "clientfiles"
* Server files are stored in a folder named "serverfiles"

## Demo
* Start the server
* Run the client. It will upload the file 'baconipsum.txt' with a number of data lines in it. It then requests one of the data lines from the server and checks its validity.
* By default the server listens on port 8080.

## Data line format
The format of lines in the data files is strictly specified by regex patterns in the client. Each data line is delimited by a newline character in the files. Each line has the form:
	ID-DETAILS

where:
	ID is of the form IDxxx, where x is a digit (there are strictly 3).
	DETAILS is some sequence of characters
