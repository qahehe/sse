/*
 * Created by helen chan  on 06/06/2021
 * Email: kaibaking@gmail.com
 * 
 */
#include "DistSSE.client.h"
#include "DistSSE.Util.h"
#include <cmath>
#include <chrono>

namespace DistSSE{

		static bool sample(double value, double rate) {
			return (value - rate) < 0.0000000000000001 ? true : false;
		}
		
		static double rand_0_to_1(unsigned int seed){ 
			srand(seed);
			return ((double) rand() / (RAND_MAX));		
		}

		static void search_log(std::string word, int counter) {
		
				std::cout << word + "\t" + std::to_string(counter)<< std::endl;
		}

		static void generation_job(Client* client, unsigned int thread_id, size_t N_entries, unsigned int step, std::atomic_size_t* entries_counter) {
			const std::string kKeyword01PercentBase    = "0.1";
		    const std::string kKeyword1PercentBase     = "1";
		    const std::string kKeyword10PercentBase    = "10";

		    const std::string kKeywordGroupBase      = "Group-";
		    const std::string kKeyword10GroupBase    = kKeywordGroupBase + "10^";

		    constexpr uint32_t max_10_counter = ~0;
		    size_t counter = thread_id;
		    std::string id_string = std::to_string( thread_id );
		        
		    uint32_t counter_10_1 = 0, counter_20 = 0, counter_30 = 0, counter_60 = 0, counter_10_2 = 0, counter_10_3 = 0, counter_10_4 = 0, counter_10_5 = 0;
		        
		    std::string keyword_01, keyword_1, keyword_10;
		    std::string kw_10_1, kw_10_2, kw_10_3, kw_10_4, kw_10_5, kw_20, kw_30, kw_60;
		    
			AutoSeededRandomPool prng;
			int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
			byte tmp[ind_len];

		//std::string l, e;

			// for gRPC
			UpdateRequestMessage request;

			ClientContext context;

			ExecuteStatus exec_status;
	
			std::unique_ptr<RPC::Stub> stub_(RPC::NewStub( grpc::CreateChannel("47.88.62.170:50051", grpc::InsecureChannelCredentials()) ) );

			std::unique_ptr<ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
		
		    for (size_t i = 0; counter < N_entries; counter += step, i++) {

				prng.GenerateBlock(tmp, sizeof(tmp));
				std::string ind = (std::string((const char*)tmp, ind_len));
		        
		        std::string ind_01 = std::string((const char*)tmp, 3);
		        std::string ind_1  = std::string((const char*)tmp + 3, 1);
		        std::string ind_10 = std::string((const char*)tmp + 4, 1);
		            
		        keyword_01  = kKeyword01PercentBase    + "_" + ind_01   + "_1"; //  randomly generated
		        keyword_1   = kKeyword1PercentBase     + "_" + ind_1    + "_1";
		        keyword_10  = kKeyword10PercentBase    + "_" + ind_10   + "_1";
		        
				// logger::log(logger::INFO) << "k_01: " << keyword_01 << std::endl;

		        writer->Write( client->gen_update_request("1", keyword_01, ind, 0) );
		        writer->Write( client->gen_update_request("1", keyword_1, ind, 0) );
		        writer->Write( client->gen_update_request("1", keyword_10, ind, 0) );
		            
				

		        ind_01 = std::string((const char*)tmp + 5, 3);
		        ind_1  = std::string((const char*)tmp + 8, 1);
		        ind_10 = std::string((const char*)tmp + 9, 1);
		            
		        keyword_01  = kKeyword01PercentBase    + "_" + ind_01   + "_2";
		        keyword_1   = kKeyword1PercentBase     + "_" + ind_1    + "_2";
		        keyword_10  = kKeyword10PercentBase    + "_" + ind_10   + "_2";
		            
		        writer->Write( client->gen_update_request("1", keyword_01, ind, 0) );
		        writer->Write( client->gen_update_request("1", keyword_1, ind, 0) );
		        writer->Write( client->gen_update_request("1", keyword_10, ind, 0) );

		            
		        if (counter_10_1 < max_10_counter) {
		            kw_10_1 = kKeyword10GroupBase  + "1_" + id_string + "_" + std::to_string(counter_10_1);
		              
				    if((i+1)%10 == 0)
				    {
				    	if (logger::severity() <= logger::DBG) {
				    	    logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_1 << std::endl;
				        }
				        counter_10_1++;
				    }
		        }
		        if (counter_20 < max_10_counter) {
		            kw_20 = kKeywordGroupBase  + "20_" + id_string + "_" + std::to_string(counter_20);
		            
		            if((i+1)%20 == 0)
		            {
		                if (logger::severity() <= logger::DBG) {
		                    logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_20 << std::endl;
		                }
		                    counter_20++;
		            }
		        }
		        if (counter_30 < max_10_counter) {
		            kw_30 = kKeywordGroupBase  + "30_" + id_string + "_" + std::to_string(counter_30);
		                
		            if((i+1)%30 == 0)
		            {
		                if (logger::severity() <= logger::DBG) {
		                    logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_30 << std::endl;
		                }
		                counter_30++;
		            }
		        }
		        if (counter_60 < max_10_counter) {
		            kw_60 = kKeywordGroupBase  + "60_" + id_string + "_" + std::to_string(counter_60);
		                
		            if((i+1)%60 == 0)
		            {
		                if (logger::severity() <= logger::DBG) {
		                    logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_60 << std::endl;
		                }
		                counter_60++;
		            }
		        }
		        if (counter_10_2 < max_10_counter) {
		            kw_10_2 = kKeyword10GroupBase  + "2_" + id_string + "_" + std::to_string(counter_10_2);

		            if((i+1)%100 == 0)
		            {
		                if (logger::severity() <= logger::DBG) {
		                    logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_2 << std::endl;
		                }
		                counter_10_2++;
		            }
		        }
		        if (counter_10_3 < max_10_counter) {
		            kw_10_3 = kKeyword10GroupBase  + "3_" + id_string + "_" + std::to_string(counter_10_3);

		            if((i+1)%((size_t)(1e3)) == 0)
		            {
		                if (logger::severity() <= logger::DBG) {
		                    logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_3 << std::endl;
		                }
		                counter_10_3++;
		            }
		        }
		        if (counter_10_4 < max_10_counter) {
		            kw_10_4 = kKeyword10GroupBase  + "4_" + id_string + "_" + std::to_string(counter_10_4);
		                
		            if((i+1)%((size_t)(1e4)) == 0)
		            {
		                if (logger::severity() <= logger::DBG) {
		                    logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_4 << std::endl;
		                }
		                counter_10_4++;
		            }
		        }
		        if (counter_10_5 < max_10_counter) {
		            kw_10_5 = kKeyword10GroupBase  + "5_" + id_string + "_" + std::to_string(counter_10_5);
		               
		            if((i+1)%((size_t)(1e5)) == 0)
		            {
		                if (logger::severity() <= logger::DBG) {
		                    logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_5 << std::endl;
		                }
		                counter_10_5++;
		            }
		        }

		                
		        (*entries_counter)++;
		  		if (((*entries_counter) % 10) == 0) {
                    logger::log(logger::INFO) << "Random DB generation: " << (*entries_counter) << " entries generated\r" << std::flush;
                }

		        writer->Write( client->gen_update_request("1", kw_10_1, ind, 0) );
		        writer->Write( client->gen_update_request("1", kw_10_2, ind, 0));
		        writer->Write( client->gen_update_request("1", kw_10_3, ind, 0));
		        writer->Write( client->gen_update_request("1", kw_10_4, ind, 0));
		        writer->Write( client->gen_update_request("1", kw_10_5, ind, 0));
		        writer->Write( client->gen_update_request("1", kw_20, ind, 0));
		        writer->Write( client->gen_update_request("1", kw_30, ind, 0));
		        writer->Write( client->gen_update_request("1", kw_60, ind, 0));

		    }
		    
			// now tell server we have finished
			writer->WritesDone();
	    	Status status = writer->Finish();
		assert(status.ok());

		    std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: (" + std::to_string(counter_10_1) + ", " 
		                    + std::to_string(counter_10_2) + ", "+ std::to_string(counter_10_3) + ", "+ std::to_string(counter_10_4) + ", "
		                    + std::to_string(counter_10_5)  + ")";
		    logger::log(logger::INFO) << log << std::endl;
		    }


			void gen_db (Client& client, size_t N_entries, unsigned int n_threads)
		    {
		        std::atomic_size_t entries_counter(0);

		        // client->start_update_session();

		        // unsigned int n_threads = std::thread::hardware_concurrency();
		        std::vector<std::thread> threads;
		        // std::mutex rpc_mutex;
		        
				struct timeval t1, t2;	

				gettimeofday(&t1, NULL);
				
		        for (unsigned int i = 0; i < n_threads; i++) {
		            threads.push_back(std::thread(generation_job, &client, i, N_entries, n_threads, &entries_counter));
		        }

		        for (unsigned int i = 0; i < n_threads; i++) {
		            threads[i].join();
		        }

				gettimeofday(&t2, NULL);

				logger::log(logger::INFO) <<"total update time: "<<((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec -t1.tv_usec) /1000.0<<" ms" <<std::endl;

		        // client->end_update_session();
		    }

			void Subjob(Client *client, unsigned int thread_id, unsigned int step, std::atomic_size_t *entries_counter){
				size_t counter = thread_id;      //counter =线程id
				std::string id_string = std::to_string(thread_id); 
				//gRPC  update操作
				UpdateRequestMessage request;
				ClientContext context;
				ExecuteStatus exec_status;
				std::unique_ptr<RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("127.0.0.1:50051", grpc::InsecureChannelCredentials())));
				std::unique_ptr<ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
				std::string keyword, id;
				std::ifstream myfile("/home/helen/fast/1.txt",std::ios::in);
				//std::ifstream myfile("/home/helen/fastio/data/change.txt",std::ios::in);
				if(!myfile){
					logger::log(logger::ERROR) << "读取错误"<< std::endl;
					exit(-1);
				}
				std::string line;
				while(getline(myfile,line)){
					std::stringstream ss(line);
					ss>>keyword>>id;
					writer->Write(client->gen_update_request("1", keyword, id,0));
				}
				myfile.close();
				// 向服务器说明我们更新完事了
				writer->WritesDone();
				Status status = writer->Finish();
				assert(status.ok());

				std::string log = "Random DB generation: 随便加！";
				logger::log(logger::INFO) << log << std::endl;
			}
			//文件数据导入
			void File_Get(Client &client,unsigned int n_threads){
				std::atomic_size_t entries_counter(0);
				std::vector<std::thread> threads;
				struct timeval t1, t2;
				gettimeofday(&t1, NULL);
				// for (unsigned int i = 0; i < n_threads; i++)
				// {
				//     threads.push_back(std::thread(Subjob, &client, i, n_threads, &entries_counter));
				// }
				// for (unsigned int i = 0; i < n_threads; i++)
				// {
				//     threads[i].join();
				// }
				Subjob(&client,1,4,0);
				gettimeofday(&t2, NULL);
				logger::log(logger::INFO) << "total update time: " << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms" << std::endl;
			}

}//namespace DistSSE
