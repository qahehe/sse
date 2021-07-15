/*
 * Created by helen chan  on 06/06/2021
 * Email: kaibaking@gmail.com
 * 
 */
#ifndef DISTSSE_SERVER_H
#define DISTSSE_SERVER_H

#include <grpc++/grpc++.h>

#include "DistSSE.grpc.pb.h"

#include "DistSSE.Util.h"

#include "logger.h"

#include <unordered_set>


#define min(x ,y) ( x < y ? x : y)

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerWriter;
using grpc::Status;

using namespace CryptoPP;

byte iv_s[17] = "0123456789abcdef";

namespace DistSSE{

class DistSSEServiceImpl final : public RPC::Service {
private:	
	static rocksdb::DB* ss_db;
    int MAX_THREADS;
	rocksdb::Options options;
public:
	DistSSEServiceImpl(const std::string db_path, int concurrent){
		signal(SIGINT, abort);
    	options.create_if_missing = true;
	    Util::set_db_common_options(options);
		rocksdb::Status s1 = rocksdb::DB::Open(options, db_path, &ss_db);
		MAX_THREADS = concurrent; 
	}

	static void abort( int signum )
	{
		delete ss_db;
		logger::log(logger::INFO)<< "abort: "<< signum <<std::endl;
	   	exit(signum);
	}
	//rocksdb存储与获取
	static int store(rocksdb::DB* &db, const std::string l, const std::string e){
		rocksdb::Status s; 		
		rocksdb::WriteOptions write_option = rocksdb::WriteOptions();	
		s = db->Put(write_option, l, e);
		if (s.ok())	return 0;
		else return -1;
	}

	static std::string get(rocksdb::DB* &db, const std::string l){
		std::string tmp;
		rocksdb::Status s;
		s = db->Get(rocksdb::ReadOptions(), l, &tmp);
		if (s.ok())	return tmp;
		else return "";
	}


	static void parse (std::string str, std::string& op, std::string& ind, std::string& key) {
		op = str.substr(0, 1);		
		ind = str.substr(1, 8); // TODO
		key = str.substr(9, AES128_KEY_LEN);
	}
	
	std::string recover_st(std::string old_st, std::string key) {
		std::string new_st;
		try
		{
			CFB_Mode< AES >::Decryption d;
			d.SetKeyWithIV((byte*) key.c_str(), AES128_KEY_LEN, iv_s, (size_t)AES::BLOCKSIZE); 
			byte tmp_new_st[old_st.length()];
			d.ProcessData(tmp_new_st, (byte*) old_st.c_str(), old_st.length());
			new_st = std::string((const char*)tmp_new_st, old_st.length());
		}
		catch(const CryptoPP::Exception& e)
		{
			std::cerr << "in generate_st() " << e.what()<< std::endl;
			exit(1);
		}
		// logger::log(logger::INFO) << "new_st: "<<new_st<<std::endl;
		// logger::log(logger::INFO) << "old_st: "<<old_st<<std::endl;
		// logger::log(logger::INFO) << "random_key: "<<key <<std::endl;
		return new_st;
	}
	//搜索
	void search(std::string tw, std::string st, size_t uc, std::unordered_set<std::string>& ID){
		std::vector<std::string> op_ind;
		std::string op, ind, rand_key;
		std::string _st, l, e, value;
		int counter = 0;
		std::unordered_set<std::string> result_set; //结果集
		std::unordered_set<std::string> delete_set;  //删除表
	    _st = st;

		logger::log(logger::INFO) << "server searching... "<< uc <<std::endl;
		for(size_t i = 1; i <= uc; i++) {
			l = Util::H1(tw + _st);
			e = get(ss_db, l);
			if(e == "") {
				logger::log(logger::ERROR)<< "FUCKING ERROR!"  <<std::endl;
				break;
			}
			//assert(e != "");
			value = Util::Xor( e, Util::H2(tw + _st) );   // e异或H2(tw+_st) = value= op + ind + random_key
            parse(value, op, ind, rand_key); 
			if (op == "0") {
				delete_set.insert(ind);		
			}
			else if(op == "1") {
				std::unordered_set<std::string>::iterator it = delete_set.find(ind);
				if (it != delete_set.end() ) {
					delete_set.erase(ind);				
				}else{
					result_set.insert(ind);				
				}
			}
			_st=recover_st( _st, rand_key);
		}
		ID =result_set;
	}

// server RPC
	Status search(ServerContext* context, const SearchRequestMessage* request,
                  ServerWriter<SearchReply>* writer)  {
		std::string st = request->st();
		std::string tw = request->tw();	
		size_t uc = request->uc();
		struct timeval t1, t2;
		std::unordered_set<std::string> ID;

		logger::log(logger::INFO) << "搜索开始！ " <<std::endl;
		gettimeofday(&t1, NULL);
		search(tw, st, uc, ID);
		gettimeofday(&t2, NULL);
  		logger::log(logger::INFO) <<"Result.size():"<< ID.size() <<" ,search time: "<< ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) /1000.0/ID.size()<<" ms" <<std::endl;
		
		SearchReply reply;
		for(auto it:ID){
			reply.set_ind(it);
			writer->Write(reply);
		}
		logger::log(logger::INFO) << "搜索结束！" <<std::endl;
	    return Status::OK;
  	}
	// update()实现单次更新操作
	Status update(ServerContext* context, const UpdateRequestMessage* request, ExecuteStatus* response) {
		std::string l = request->l();
		std::string e = request->e();
		logger::log(logger::INFO) <<"in once update"<<std::endl;
		int status = store(ss_db, l, e);
		if(status != 0) {
			response->set_status(false);
			return Status::CANCELLED;
		}
		response->set_status(true);
		return Status::OK;
	}
	
	// batch_update()实现批量更新操作
	Status batch_update(ServerContext* context, ServerReader< UpdateRequestMessage >* reader, ExecuteStatus* response) {
		std::string l;
		std::string e;
		// TODO 读取数据库之前要加锁，读取之后要解锁
		UpdateRequestMessage request;
		while (reader->Read(&request)){
			l = request.l();
			e = request.e();
			store(ss_db, l, e);
		}
		response->set_status(true);
		return Status::OK;
	}
};

}// namespace DistSSE

rocksdb::DB* DistSSE::DistSSEServiceImpl::ss_db;

void RunServer(std::string db_path,int concurrent) {
  std::string server_address("0.0.0.0:50051");
  DistSSE::DistSSEServiceImpl service(db_path, concurrent);
  ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  DistSSE::logger::log(DistSSE::logger::INFO) << "Server listening on " << server_address << std::endl;
  server->Wait();
}

#endif // DISTSSE_SERVER_H
