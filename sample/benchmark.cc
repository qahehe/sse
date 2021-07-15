#include "ECSSE.client.h"

#include "logger.h"

using ECSSE::SearchRequestMessage;

int main(int argc, char** argv) {
  // Instantiate the client and channel isn't authenticated
	ECSSE::Client client(grpc::CreateChannel("127.0.0.1:50051", grpc::InsecureChannelCredentials()), std::string(argv[1]));
	
	if (argc < 4) {
		std::cerr<<"argc error"<<std::endl;	
		exit(-1);
	}
	
	int threads_num = atoi(argv[2]);
	int max = atoi(argv[3]);

	std::string keyword;
	std::string prefix = "Group10^";


	std::cout << "benchmark begin!" << std::endl;
	for(int j = 0; j < threads_num; j++)
		for(int i =1; i < 6; i++) 
			for(int k = 0; k < max; k++) {
				keyword = prefix + std::to_string(i) + "_" + std::to_string(j) + "_" + std::to_string(k);
				client.search(keyword);
	}
	std::cout << "search done."<< std::endl;
	
	return 0;
}

//benchmark 搜索的基准测试
// /.benchmark  [db_path] [threads_num] [max]