/*
 * Created by helen chan  on 06/06/2021
 * Email: kaibaking@gmail.com
 * 
 */
#include "DistSSE.client.h"

#include "logger.h"

using DistSSE::SearchRequestMessage;

int main(int argc, char** argv) {
  // Instantiate the client and channel isn't authenticated
	DistSSE::Client client(grpc::CreateChannel("127.0.0.1:50051", grpc::InsecureChannelCredentials()), std::string(argv[1]));
	
	if (argc < 3) {
		std::cerr<<"argc error"<<std::endl;	
		exit(-1);
	}
	int threads_num = atoi(argv[2]);
    std::string keyword = "312";
	//std::cin>>keyword;  输入要查询的关键字
    std::cout << "search begin!" << std::endl;
    client.search(keyword);
	std::cout << "search done."<< std::endl;
	
	return 0;
}

//普通搜索实现
// /.search  [db_path] [threads_num]    