#include "DistSSE.server.h"

int main(int argc, char *argv[]){
	if (argc < 3) {
		std::cerr<<"argc error"<<std::endl;	
		exit(-1);
	}
	RunServer(std::string(argv[1]), atoi(argv[2]) );
}
























