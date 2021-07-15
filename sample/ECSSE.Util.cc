/*
 * Created by helen chan  on 06/06/2021
 * Email: kaibaking@gmail.com
 * 
 */


#include "ECSSE.Util.h"
using namespace CryptoPP;

// 系统参数
int max_keyword_length = 20;
int max_nodes_number = 10;

namespace ECSSE
{
    std::string Util::H1(const std::string message)
    {
        byte buf[SHA256::DIGESTSIZE];
        std::string salt = "01";
        SHA256().CalculateDigest(buf, (byte *)((message + salt).c_str()), message.length() + salt.length());
        return std::string((const char *)buf, (size_t)SHA256::DIGESTSIZE);
    }

    std::string Util::H2(const std::string message)
    {
        byte buf[SHA256::DIGESTSIZE];
        std::string salt = "02";
        SHA256().CalculateDigest(buf, (byte *)((message + salt).c_str()), message.length() + salt.length());
        return std::string((const char *)buf, (size_t)SHA256::DIGESTSIZE);
    }
    std::string Util::padding(const std::string str)
    {
        size_t BS = (size_t)AES::BLOCKSIZE;
        size_t pad_len = BS - str.length() % BS;
        return str + std::string(char(pad_len), pad_len);
    }

    std::string Util::remove_padding(const std::string str)
    {
        int len = str.length();
        int pad_len = int(str[len - 1]);
        bool flag = false;
        for (int i = len - pad_len; i < len; i++)
        {
            if (int(str[i]) != pad_len)
            {
                flag = true;
                break;
            }
        }
        if (flag)
            std::cout << "wrong padding" << std::endl;
        else
            return std::string(str, 0, len - pad_len);
    }

    std::string Util::Id_padding(const std::string str){
        //填充id到8byte 
        size_t BS = (size_t)AES::BLOCKSIZE/2;
        size_t pad_len = BS - str.length()%BS;
        return str + std::string(char(pad_len), pad_len);
    }

    std::string Util::remove_Id_padding(const std::string str){
        int len = str.length();
        int pad_len = int(str[len - 1]);
        bool flag = false;
        for (int i = len - pad_len; i < len; i++)
        {
            if (int(str[i]) != pad_len)
            {
                flag = true;
                break;
            }
        }
        if (flag)
            std::cout << "wrong padding" << std::endl;
        else
            return std::string(str, 0, len - pad_len);
    }
    
    std::string Util::Xor(const std::string s1, const std::string s2)
    {
        // std::cout<< "in len = "<< s1.length()<<", s1 = "<<s1<<std::endl;
        std::string result = s1;
        if (s1.length() > s2.length())
        {
            //ERROR
            std::cout << "not sufficient size: " << s1.length() << ", " << s2.length() << std::endl;
            return "";
        }

        for (int i = 0; i < result.length(); i++)
        {
            result[i] ^= s2[i];
        }
        return result;
    }

    void Util::split(const std::string &s, char delim, std::set<std::string> &ID)
    {
        std::stringstream ss;
        ss.str(s);
        std::string item;
        while (std::getline(ss, item, delim))
        {
            ID.insert(item);
        }
    }

    void Util::split(const std::string &s, char delim, std::vector<std::string> &elems)
    {
        std::stringstream ss;
        ss.str(s);
        std::string item;
        while (std::getline(ss, item, delim))
        {
            elems.push_back(item);
        }
    }

    std::string Util::dec_token(const void *key, int key_len, const void *iv, std::string enc_token)
    {
        // 仅仅用来测试token是否加密正确，最后返回的字符串需要去掉padding
        std::string token;
        try
        {
            CFB_Mode<AES>::Decryption d;

            d.SetKeyWithIV((byte *)key, key_len, (byte *)iv, (size_t)AES::BLOCKSIZE);
            size_t cipher_length = enc_token.length();
            byte plain_text[cipher_length];
            //cout<<enc_token<<endl;
            d.ProcessData(plain_text, (byte *)enc_token.c_str(), cipher_length);
            token = std::string((const char *)plain_text, cipher_length);
        }
        catch (const CryptoPP::Exception &e)
        {
            std::cerr << "in Dec() " << e.what() << std::endl;
            exit(1);
        }
        return remove_padding(token);
    }

    //AES解密函数
    void Util::descrypt(std::string key, std::string ciphertext,std::string &plaintext){
        try{
            CFB_Mode< AES >::Decryption e;
            e.SetKeyWithIV((byte*)key.c_str(), AES128_KEY_LEN, iv_s, (size_t)AES::BLOCKSIZE); 
            StringSource s(ciphertext, true, 
                new StreamTransformationFilter(e,
                    new StringSink(plaintext)
                ) 
            );
        }catch(const CryptoPP::Exception& e)
        {
            std::cerr << "in descrypt()解密出问题 " << e.what()<< std::endl;
            exit(1);
        }
    }

    //AES加密函数
    void Util::encrypt(std::string key, std::string plaintext,std::string &ciphertext){
        try {
            CFB_Mode< AES >::Encryption e;
            e.SetKeyWithIV((byte*)key.c_str(), AES128_KEY_LEN, iv_s, (size_t)AES::BLOCKSIZE); 
            StringSource s(plaintext, true, 
                new StreamTransformationFilter(e,
                    new StringSink(ciphertext)
                ) 
            );
        }catch(const CryptoPP::Exception& e)
        {
            std::cerr << "in gen_enc_token() 在生成kw中出问题 " << e.what()<< std::endl;
            exit(1);
        }
    }

    void Util::print(std::string str){
        for(int i =0;i<str.size();i++){
            int c = (unsigned char)str[i];
            std::cout << c << " ";
        }
        std::cout<<std::endl;
    }


    std::string Util::str2hex(const std::string &input)
    {
        static const char *const lut = "0123456789ABCDEF";
        size_t len = input.length();

        std::string output;
        output.reserve(2 * len);
        for (size_t i = 0; i < len; ++i)
        {
            const unsigned char c = input[i];
            output.push_back(lut[c >> 4]);
            output.push_back(lut[c & 15]);
        }
        return output;
    }

    std::string Util::hex2str(const std::string &input)
    {
        static const char *const lut = "0123456789ABCDEF";
        size_t len = input.length();
        if (len & 1)
            throw std::invalid_argument("odd length");

        std::string output;
        output.reserve(len / 2);
        for (size_t i = 0; i < len; i += 2)
        {
            char a = input[i];
            const char *p = std::lower_bound(lut, lut + 16, a);
            if (*p != a)
                throw std::invalid_argument("not a hex digit");

            char b = input[i + 1];
            const char *q = std::lower_bound(lut, lut + 16, b);
            if (*q != b)
                throw std::invalid_argument("not a hex digit");

            output.push_back(((p - lut) << 4) | (q - lut));
        }
        return output;
    }

    void Util::set_db_common_options(rocksdb::Options &options)
    {

        options.create_if_missing = true;
        //       options.statistics = rocksdb::CreateDBStatistics();

        /*		rocksdb::CuckooTableOptions cuckoo_options;
            cuckoo_options.identity_as_first_hash = false;
            cuckoo_options.hash_table_ratio = 0.9;
            
            
            //        cuckoo_options.use_module_hash = false;
            //        cuckoo_options.identity_as_first_hash = true;
            
            options.table_cache_numshardbits = 4;
            options.max_open_files = -1;
            
            
            
            
            options.table_factory.reset(rocksdb::NewCuckooTableFactory(cuckoo_options));
            
            
            options.compression = rocksdb::kNoCompression;
            options.bottommost_compression = rocksdb::kDisableCompressionOption;
            
            options.compaction_style = rocksdb::kCompactionStyleLevel;
            options.info_log_level = rocksdb::InfoLogLevel::INFO_LEVEL;
            
            
            
            options.delayed_write_rate = 8388608;
            options.max_background_compactions = 20;
            
            options.allow_mmap_reads = true;
            //options.new_table_reader_for_compaction_inputs = true;
            
            options.max_bytes_for_level_base = 4294967296;
            options.arena_block_size = 134217728;
            options.level0_file_num_compaction_trigger = 10;
            options.level0_slowdown_writes_trigger = 16;
            options.hard_pending_compaction_bytes_limit = 137438953472;
            options.target_file_size_base=201327616;
            options.write_buffer_size=1073741824;
            
            options.optimize_filters_for_hits = true;
*/
        /*
			std::shared_ptr<rocksdb::Cache> cache = rocksdb::NewLRUCache(0LL);
			rocksdb::BlockBasedTableOptions table_options;
			table_options.block_cache = cache;

			// set compressed block cache = 4M
			std::shared_ptr<rocksdb::Cache> compressed_cache = rocksdb::NewLRUCache(0LL);
			table_options.block_cache_compressed = compressed_cache;
			table_options.no_block_cache = true;
			options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options));
		*/

        // use direct I/O
        //options.use_direct_reads = true;
        //options.use_direct_io_for_flush_and_compaction = true;
    }

} // namespace ECSSE
