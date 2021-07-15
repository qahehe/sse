/*
 * Created by helen chan  on 06/06/2021
 * Email: kaibaking@gmail.com
 * 
 */
#ifndef ECSSE_CLIENT_H
#define ECSSE_CLIENT_H
#include <bits/stdc++.h>
#include <rocksdb/db.h>
#include <grpc++/grpc++.h>
#include <ECSSE.Util.h>
#include "ECSSE.grpc.pb.h"
#include "logger.h"
using grpc::Channel;
using grpc::ClientAsyncResponseReaderInterface;
using grpc::ClientContext;
using grpc::ClientReaderInterface;
using grpc::ClientWriterInterface;

//用于生成子密钥，主密钥和初始化向量
byte k[17] = "0123456789abcdef";
byte iv_s[17] = "0123456789abcdef";

using grpc::Status;
namespace ECSSE
{

    class Client
    {
    public:
        Client(std::shared_ptr<Channel> channel, std::string db_path) : stub_(RPC::NewStub(channel))
        {
            rocksdb::Options options;         //rocksdb的设置
            options.create_if_missing = true; //设定如果不存在就创建
            rocksdb::Status status = rocksdb::DB::Open(options, db_path, &db);

            //读取updatecnt到内存里去
            rocksdb::Iterator *it = db->NewIterator(rocksdb::ReadOptions());
            std::string key;
            size_t counter = 0;
            size_t value;
            for (it->SeekToFirst(); it->Valid(); it->Next())
            {
                key = it->key().ToString();
                value = std::stoi(it->value().ToString());
                uc[key] = value;
                counter++;
            }
            assert(it->status().ok()); //判断数据库状态是否正常
            delete it;
            std::cout << "目前有的keywords个数：" << counter << std::endl;
        }
        ~Client()
        {
            size_t keycnt = 0;
            std::map<std::string, size_t>::iterator ut;
            for (ut = uc.begin(); ut != uc.end(); ++ut)
            {
                store(ut->first, std::to_string(ut->second));
                logger::log(logger::INFO) <<ut->first<<" "<<ut->second<< std::endl;
                keycnt++;
            }
            std::cout << "已存keyword状态数：" << keycnt << std::endl;
        }

        //字典存储与获取
        int store(const std::string key, const std::string value)
        {
            rocksdb::Status s = db->Delete(rocksdb::WriteOptions(), key);
            s = db->Put(rocksdb::WriteOptions(), key, value);
            if (s.ok())
                return 0;
            else
                return -1;
            assert(s.ok());
        }
        std::string get(const std::string key)
        {
            std::string temp;
            rocksdb::Status s = db->Get(rocksdb::ReadOptions(), key, &temp);
            if (s.ok())
                return temp;
            else
                return "";
        }

        //获取更新次数/设定更新次数/更新增加一次
        int get_update_time(std::string keyword)
        {
            int update_time;
            std::map<std::string, size_t>::iterator it;
            it = uc.find(keyword);
            if (it != uc.end())
            {
                update_time = it->second;
            }
            else
            {
                update_time = 0;
                set_update_time(keyword, 0);
            }
            return update_time;
        }

        void set_update_time(std::string keyword, size_t update_time)
        {
            std::lock_guard<std::mutex> lock(uc_mtx);
            uc[keyword] = update_time;
        }

        void increase_update_time(std::string keyword)
        {
            set_update_time(keyword, get_update_time(keyword) + 1);
        }

        //生成Kw,多次修改
        std::string gen_enc_token(const std::string token){
            // 使用padding方式将所有字符串补齐到16的整数倍长度
            std::string token_padding;
            std::string enc_token;
            try {
                CFB_Mode< AES >::Encryption e;
                //主密钥和初始化向量固定，对关键字进行padding使得F(K,w)->K_w
                e.SetKeyWithIV(k, AES128_KEY_LEN, iv_s, (size_t)AES::BLOCKSIZE); //设定masterkey
                token_padding = Util::padding(token);
                StringSource s(token_padding, true, 
                    new StreamTransformationFilter(e,
                        new StringSink(enc_token)
                    ) 
                ); 

            }
            catch(const CryptoPP::Exception& e)
            {
                std::cerr << "in gen_enc_token() 在生成kw中出问题 " << e.what()<< std::endl;
                exit(1);
            }
            return enc_token;
        }

        //生成状态的方法
        std::string gen_st(std::string &keyword, size_t c,std::string &K_w)
        {
            //生成状态st_c 
            std::string st_c;
            std::string w_str;
            try
            {
                w_str = K_w + std::to_string(c);
                st_c = Util::H2(w_str);
                st_c =st_c.substr(0,16); //取前16位字节
            }
            catch (const CryptoPP::Exception &e)
            {
                std::cerr << "in gen_st() 生成状态stc中出问题" << e.what() << std::endl;
                exit(1);
            }
            return st_c;
        }
        void gen_update_token(std::string op, std::string keyword, std::string id, std::string &l, std::string &E)
        {
            std::string cipherid;
            std::string enc;
            try
            {
                std::string enc_token;
                std::string token_padding;
                std::string old_st, new_st;
                std::string K_w, id_padding;
                //std::string enc;
                size_t c = get_update_time(keyword);
                c++;
                set_update_time(keyword, c);     //缓存更新
                K_w = gen_enc_token(keyword);    //生成子密钥Kw
                old_st = gen_st(keyword, c - 1,K_w); //旧状态16字节
                new_st = gen_st(keyword, c,K_w);     //新状态16字节

                id_padding =Util::Id_padding(id);  //id填充到8byte
                Util::encrypt(K_w,id_padding,cipherid);     //response-id   
                //加密连接密文
                Util::encrypt(new_st, old_st, enc);

                //生成字典键值对
                l = Util::H1(new_st);
                E = Util::Xor(op + cipherid, Util::H2(new_st));
                E = E+enc;
            }
            catch (const CryptoPP::Exception &e)
            {
                std::cerr << "in gen_update_token() " << e.what() << std::endl;
                exit(1);
            }
        }

        void gen_search_token(std::string keyword, std::string &st, size_t &c)
        {
            try
            {
                c = get_update_time(keyword);
                std::string K_w = gen_enc_token(keyword);
                st = gen_st(keyword, c,K_w);
            }
            catch (const CryptoPP::Exception &e)
            {
                std::cerr << "in gen_search_token() " << e.what() << std::endl;
                exit(1);
            }
        }

        // 客户端RPC通信部分
        std::string search(const std::string keyword)
        {
            std::string st;
            size_t c;
            gen_search_token(keyword, st, c); //生成状态和次数
            logger::log(logger::INFO) <<c<<" "<<keyword<< std::endl;
            search(st, c,keyword);
            return "OK";
        }

        std::string search(const std::string st, const size_t c,const std::string keyword)
        {
            SearchRequestMessage request;
            if (c == 0)
                request.set_st(""); // TODO attentaion here !!!
            else
                request.set_st(st);
            request.set_uc(c);

            // Context for the client. It could be used to convey extra information to the server and/or tweak certain RPC behaviors.
            ClientContext context;

            // 执行RPC操作，返回类型为 std::unique_ptr<ClientReaderInterface<SearchReply>>
            std::unique_ptr<ClientReaderInterface<SearchReply>> reader = stub_->search(&context, request);
            // 读取返回列表
            std::string K_w = gen_enc_token(keyword);
            int counter = 0;
            SearchReply reply;
            while (reader->Read(&reply))
            {
                std::string id;
                Util::descrypt(K_w, reply.ind(), id);
                id = Util::remove_Id_padding(id);
                logger::log(logger::INFO) << id << std::endl;
                counter++;
            }
            logger::log(logger::INFO) << " search result: "<< counter << std::endl;
            return "OK";
        }
        Status update(UpdateRequestMessage update)
        {

            ClientContext context;

            ExecuteStatus exec_status;
            // 执行RPC
            Status status = stub_->update(&context, update, &exec_status);
            assert(status.ok());

            return status;
        }

        Status update(std::string op, std::string keyword, std::string id)
        {
            ClientContext context;

            ExecuteStatus exec_status;
            // 执行RPC
            std::string l, e,enc;
            
            gen_update_token(op, keyword, id, l, e);
            UpdateRequestMessage update_request;
            update_request.set_l(l);
            update_request.set_e(e);
            //logger::log(logger::INFO) <<"wrong?"<< std::endl;
            Status status = stub_->update(&context, update_request, &exec_status);
            if (status.ok())
                //increase_update_time(keyword); // TODO
            assert(status.ok());
            return status;
        }

        UpdateRequestMessage gen_update_request(std::string op, std::string keyword, std::string id)
        {
            try
            {
                UpdateRequestMessage msg;
                std::string old_st, new_st, l, E, cipherid, K_w,enc;
                size_t c = get_update_time(keyword);
                c++;
                set_update_time(keyword, c);
                K_w = gen_enc_token(keyword);
                new_st = gen_st(keyword, c,K_w);
                old_st = gen_st(keyword, c-1,K_w);
                //更新
                std::string id_padding =Util::Id_padding(id);  //id填充到8byte
                Util::encrypt(K_w,id_padding,cipherid);
                //加密连接密文
                Util::encrypt(new_st, old_st, enc);

                //生成字典键值对
                l = Util::H1(new_st);
                E = Util::Xor(op + cipherid, Util::H2(new_st));
                E = E + enc;
                msg.set_l(l);
                msg.set_e(E);
                //最终应该是 E :25Byte  +  l :32byte 
                return msg;
            }
            catch (const CryptoPP::Exception &e)
            {
                std::cerr << "in gen_update_request() " << e.what() << std::endl;
                exit(1);
            }
        }
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

    private:
        rocksdb::DB *db;
        std::map<std::string, size_t> uc; //client存的状态！
        std::mutex uc_mtx;
        std::unique_ptr<RPC::Stub> stub_;
    };
}
#endif