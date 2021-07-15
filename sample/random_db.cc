#include "ECSSE.db_generator.h"

int main(int argc, char **argv)
{
    // Instantiate the client and channel isn't authenticated

    if (argc < 4)
    {
        std::cerr << "argc error" << std::endl;
        exit(-1);
    }
    size_t N_entry = atoi(argv[2]);
    std::string db_path = std::string(argv[1]);
    size_t thread_num = atoi(argv[3]);
    ECSSE::Client client(grpc::CreateChannel("127.0.0.1:50051", grpc::InsecureChannelCredentials()), std::string(argv[1]));
    std::cout << "update begin..." << std::endl;
    ECSSE::gen_db(client, N_entry,thread_num);
    std::cout << "update done." << std::endl;
    return 0;
}

//随机数据库生成
/*
    ./random_db [db_path] [N_entry] [thread_num]
*/
