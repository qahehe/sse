/*
 * Created by helen chan  on 06/06/2021
 * Email: kaibaking@gmail.com
 * 
 */
#include "DistSSE.db_generator.h"

int main(int argc, char **argv)
{
    // Instantiate the client and channel isn't authenticated

    if (argc < 3)
    {
        std::cerr << "argc error" << std::endl;
        exit(-1);
    }
    std::string db_path = std::string(argv[1]);
    size_t thread_num = atoi(argv[2]);
    DistSSE::Client client(grpc::CreateChannel("127.0.0.1:50051", grpc::InsecureChannelCredentials()), std::string(argv[1]));
    std::cout << "update begin..." << std::endl;
    DistSSE::File_Get(client,thread_num);
    std::cout << "update done." << std::endl;
    return 0;
}

//取数据进行更新
/*
    ./update [db_path] [thread_num]
*/
