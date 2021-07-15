/*
 * Created by helen chan  on 06/06/2021
 * Email: kaibaking@gmail.com
 * 
 */
#ifndef DISTSSE_CLIENT_H
#define DISTSSE_CLIENT_H

#include <grpc++/grpc++.h>

#include "DistSSE.grpc.pb.h"

#include "DistSSE.Util.h"

#include "logger.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReaderInterface;
using grpc::ClientWriterInterface;
using grpc::ClientAsyncResponseReaderInterface;

using grpc::Status;

using namespace CryptoPP;

// 用来生成 kw
byte k_s[17] = "0123456789abcdef";
byte iv_s[17] = "0123456789abcdef";

extern int max_keyword_length;
extern int max_nodes_number;

namespace DistSSE{
class Client {
private:
 	std::unique_ptr<RPC::Stub> stub_;
	rocksdb::DB* cs_db;
	//rocksdb::DB* trace_db;
	std::mutex st_mtx;
	std::mutex uc_mtx;
	std::map<std::string, std::string> st_mapper;	
	std::map<std::string, size_t> uc_mapper;

public:

  	Client(std::shared_ptr<Channel> channel, std::string db_path) : stub_(RPC::NewStub(channel)){
		rocksdb::Options options;
    	options.create_if_missing = true;
    	rocksdb::Status status = rocksdb::DB::Open(options, db_path , &cs_db);
		// load all sc, uc to memory
		rocksdb::Iterator* it = cs_db->NewIterator(rocksdb::ReadOptions());
		std::string key;
		size_t counter = 0;
	  	for (it->SeekToFirst(); it->Valid(); it->Next()) {
			key = it->key().ToString(); 
			if (key[0] == 's') { 
				st_mapper[key.substr(1, key.length() - 1)] = it->value().ToString();
			}
			else{
				uc_mapper[key.substr(1, key.length() - 1)] = std::stoi(it->value().ToString());		
			}
			counter++;
	  	}
	  	assert( it->status().ok() ); // Check for any errors found during the scan
	  	delete it;
		std::cout << "Just remind, previous keywords: "<< counter <<std::endl;
	}

    ~Client() {
		// must store 'sc' and 'uc' to disk 
		size_t keyword_counter = 0;
		std::map<std::string, std::string>::iterator it;
		for ( it = st_mapper.begin(); it != st_mapper.end(); ++it) {
			store("s" + it->first, it->second);
			keyword_counter++;
		}
		
		std::map<std::string, size_t>::iterator ut;
		for ( ut = uc_mapper.begin(); ut != uc_mapper.end(); ++ut) {
			store("u" + ut->first, std::to_string(ut->second));
		}
		std::cout<< "Total keyword: " << keyword_counter <<std::endl;
		std::cout<< "Bye~ " <<std::endl;
	}

	//rocksdb存储状态键值对
	int store(const std::string k, const std::string v){
		rocksdb::Status s = cs_db->Delete(rocksdb::WriteOptions(), k);
		s = cs_db->Put(rocksdb::WriteOptions(), k, v);
		if (s.ok())	return 0;
		else return -1;
		assert(s.ok());
	}

	std::string get(const std::string k) {
		std::string tmp;
		rocksdb::Status s = cs_db->Get(rocksdb::ReadOptions(), k, &tmp);
		if (s.ok())	return tmp;
		else return "";
	}
	//获得状态st
	std::string get_st(std::string keyword) {
		std::string st;
		std::map<std::string, std::string>::iterator it;		
		it = st_mapper.find(keyword);
		if (it != st_mapper.end()) {
			st = it->second;
		}
		else {
			byte _st[AES128_KEY_LEN];
			AutoSeededRandomPool rnd;
			rnd.GenerateBlock(_st, AES128_KEY_LEN);
			st = std::string((const char*)_st, AES128_KEY_LEN);
			set_st(keyword, st); // cache search_time into sc_mapper 
			logger::log(logger::INFO) <<"In get_st: " << st << std::endl; 
		}
		return st;
	}
	//设定最新状态
	int set_st(std::string keyword, std::string new_st) {
        {
		    std::lock_guard<std::mutex> lock(st_mtx);		
			st_mapper[keyword] = new_st;
		}
		return 0;
	}
	//获得更新次数
	int get_update_time(std::string keyword) {
		int update_time;
		std::map<std::string, size_t>::iterator it;
		it = uc_mapper.find(keyword);
		if (it != uc_mapper.end()){
			update_time = it->second;
		}
		else{
			update_time = 0;
			set_update_time(keyword, 0);
		}
		return update_time;
	}
	//设定更新次数
	int set_update_time(std::string keyword, size_t update_time){
		{
			std::lock_guard<std::mutex> lock(uc_mtx);
			uc_mapper[keyword] = update_time;
		}		
		return 0;
	}
	
	void increase_update_time(std::string keyword) {
		set_update_time(keyword, get_update_time(keyword) + 1);
	}

	//生成tw
	std::string gen_enc_token(const std::string token){
		// 使用padding方式将所有字符串补齐到16的整数倍长度
		std::string token_padding;
		std::string enc_token;
		try {
			CFB_Mode< AES >::Encryption e;
			e.SetKeyWithIV(k_s, AES128_KEY_LEN, iv_s, (size_t)AES::BLOCKSIZE); // so `key` and `iv` is fixed now
			token_padding = Util::padding(token);
			byte cipher_text[token_padding.length()];
			e.ProcessData(cipher_text, (byte*) token_padding.c_str(), token_padding.length());	
			enc_token = std::string((const char*) cipher_text, token_padding.length());
		}
		catch(const CryptoPP::Exception& e)
		{
			std::cerr << "in gen_enc_token() " << e.what()<< std::endl;
			exit(1);
		}
		return enc_token;
	}
	//生成新的状态st,并返回新的密钥k
	void gen_new_st(std::string old_st, std::string& key, std::string& new_st) {
		byte rand_key[AES128_KEY_LEN];
		try {
			AutoSeededRandomPool rnd;
			// Generate a random str
			rnd.GenerateBlock(rand_key, AES128_KEY_LEN);
			// key is for returning
			key = std::string((const char*)rand_key, AES128_KEY_LEN);
			CFB_Mode< AES >::Encryption e;
			e.SetKeyWithIV(rand_key, AES128_KEY_LEN, iv_s, (size_t)AES::BLOCKSIZE); 
			byte tmp_new_st[old_st.length()];
			e.ProcessData(tmp_new_st, (byte*) old_st.c_str(), old_st.length());
			new_st = std::string((const char*)tmp_new_st, old_st.length());
		} catch(const CryptoPP::Exception& e) {
			std::cerr << "in gen_new_st() " << e.what()<< std::endl;
			exit(1);
		}
	}
	//恢复状态st
	void recover_st(std::string new_st, std::string key, std::string& old_st) {
		try {
			CFB_Mode< AES >::Decryption d;
			d.SetKeyWithIV((byte*) key.c_str(), AES128_KEY_LEN, iv_s, (size_t)AES::BLOCKSIZE); 
			byte tmp_old_st[new_st.length()];
			d.ProcessData(tmp_old_st, (byte*) new_st.c_str(), new_st.length());
			old_st = std::string((const char*)tmp_old_st, new_st.length());
		}
		catch(const CryptoPP::Exception& e)
		{
			std::cerr << "in recover_st() " << e.what()<< std::endl;
			exit(1);
		}
	}
	//验证状态st
	void verify_st() {
		std::string old_st = "0000000000000000", new_st, key;
		gen_new_st(old_st, key, new_st);
		old_st = "fuck";
		recover_st(new_st, key, old_st);
		assert(old_st.compare("0000000000000000") == 0 );
	}
	//生成更新令牌
	void gen_update_token(std::string op, std::string keyword, std::string ind, std::string& l, std::string& e) {
		try{
			std::string enc_token, rand_key;
			std::string tw, old_st, new_st;
			old_st = get_st(keyword);
			tw = gen_enc_token(keyword);
			gen_new_st(old_st, rand_key, new_st); // TODO
			std::string id_padding =Util::Id_padding(ind);
			l = Util::H1( tw + new_st);
			// e = Util::Xor( op + id_padding + rand_key, Util::H2(tw + new_st) );
			e = Util::Xor( op + id_padding + rand_key, Util::H2(tw + new_st));
		}
		catch(const CryptoPP::Exception& e){
			std::cerr << "in gen_update_token() " << e.what() << std::endl;
			exit(1);
		}
	}

	UpdateRequestMessage gen_update_request(std::string op, std::string keyword, std::string ind, int counter){
		try{
			std::string enc_token, rand_key;
			UpdateRequestMessage msg;
			std::string tw, old_st, new_st, l, e;
			// get update time of `w` for `node`
			logger::log(logger::INFO) << "gen_updates1 " <<std::endl;
			tw = gen_enc_token(keyword);
			old_st = get_st(keyword);
			gen_new_st(old_st, rand_key, new_st); // TODO
			std::string id_padding =Util::Id_padding(ind);
			l = Util::H1( tw + new_st);
			// e = Util::Xor(op + ind + rand_key, Util::H2(tw + new_st));
			e = Util::Xor( op + id_padding + rand_key, Util::H2(tw + new_st) );
			// logger::log(logger::INFO) <<"In gen_update_request==>  " << "st:" << new_st << ", tw: " << tw << std::endl;
			assert((op + id_padding + rand_key).length() == 25);			
			msg.set_l(l);
			msg.set_e(e);
			msg.set_counter(counter);
			set_st(keyword, new_st); // TODO
			increase_update_time(keyword);
			return msg;
		}
		catch(const CryptoPP::Exception& e){
			std::cerr << "in gen_update_request() " << e.what() << std::endl;
			exit(1);
		}
	}

	UpdateRequestMessage gen_update_request(std::string op, std::string keyword, std::string ind, int counter, std::string& new_st){
		try{
			std::string enc_token, rand_key;
			UpdateRequestMessage msg;
			std::string tw, old_st, l, e;
			tw = gen_enc_token(keyword);
			old_st = get_st(keyword);
			gen_new_st(old_st, rand_key, new_st); // TODO
			l = Util::H1( tw + new_st);
			// e = Util::Xor(op + ind + rand_key, Util::H2(tw + new_st));
			std::string id_padding =Util::Id_padding(ind);
			e = Util::Xor( op + id_padding+ rand_key, Util::H2(tw + new_st) );
			// logger::log(logger::INFO) <<"In gen_update_request==>  " << "st:" << new_st << ", tw: " << tw << std::endl;
			assert((op + ind + rand_key).length() == 25);			
			msg.set_l(l);
			msg.set_e(e);
			msg.set_counter(counter);
			set_st(keyword, new_st); // TODO
			increase_update_time(keyword);
			return msg;
		}
		catch(const CryptoPP::Exception& e){
			std::cerr << "in gen_update_request() " << e.what() << std::endl;
			exit(1);
		}
	}
	//生成搜索令牌
	void gen_search_token(std::string keyword, std::string& tw, std::string& st, size_t& uc) {
		try{
			tw = gen_enc_token(keyword);
			st = get_st(keyword);
			uc = get_update_time(keyword);
		}
		catch(const CryptoPP::Exception& e){
			std::cerr << "in gen_search_token() " <<e.what() << std::endl;
			exit(1);
		}
	}

	// 客户端RPC通信部分
	std::string search(const std::string keyword) {
		std::string tw, st;
		size_t uc;
		gen_search_token(keyword, tw, st, uc);
		search(tw, st, uc);
		return "OK";
	}
	
	std::string search(const std::string tw, const std::string st, const size_t uc) {
		// request包含 enc_token 和 st
		SearchRequestMessage request;
		if( uc == 0 ) request.set_st(""); // TODO attentaion here !!!
		else request.set_st(st);
		request.set_tw(tw);
		request.set_uc(uc);

		// Context for the client. It could be used to convey extra information to the server and/or tweak certain RPC behaviors.
		ClientContext context;

		// 执行RPC操作，返回类型为 std::unique_ptr<ClientReaderInterface<SearchReply>>
		std::unique_ptr<ClientReaderInterface<SearchReply>> reader = stub_->search(&context, request);
		
		// 读取返回列表
		int counter = 0;
		SearchReply reply;
		while (reader->Read(&reply)){
			std::string dpadid = Util::remove_Id_padding(reply.ind());
			logger::log(logger::INFO) << dpadid<<std::endl;
			counter++;
		}
		logger::log(logger::INFO) << " search result: "<< counter << std::endl;
		return "OK";
	  }

	Status update(UpdateRequestMessage update) {
		ClientContext context;
		ExecuteStatus exec_status;
		// 执行RPC
		Status status = stub_->update(&context, update, &exec_status);
		assert (status.ok());
		return status;
	}

	Status update(std::string op, std::string keyword, std::string ind) {
		ClientContext context;
		ExecuteStatus exec_status;
		// 执行RPC
		std::string l, e;
		gen_update_token(op, keyword, ind, l, e); // update(op, w, ind, _l, _e);
		UpdateRequestMessage update_request;
		update_request.set_l(l);
		update_request.set_e(e);
		Status status = stub_->update(&context, update_request, &exec_status);
		if(status.ok()) 
			increase_update_time(keyword);// TODO
		assert(status.ok());
		return status;
	}
	//批量更新
	Status batch_update(std::vector<UpdateRequestMessage> update_list) {
		UpdateRequestMessage request;
		ClientContext context;
		ExecuteStatus exec_status;
		std::unique_ptr<ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
		int i = 0;		
		while(i < update_list.size()){
			writer->Write(update_list[i]);
		}
		writer->WritesDone();
	    Status status = writer->Finish();
		return status;
	}
};

} // namespace DistSSE

#endif // DISTSSE_CLIENT_H
