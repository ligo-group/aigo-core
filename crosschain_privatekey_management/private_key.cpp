/**
* Author: wengqiang (email: wens.wq@gmail.com  site: qiangweng.site)
*
* Copyright © 2015--2018 . All rights reserved.
*
* File: private_key.cpp
* Date: 2018-01-11
*/

#include <graphene/crosschain_privatekey_management/private_key.hpp>
#include <graphene/utilities/key_conversion.hpp>
#include <fc/crypto/base58.hpp>
#include <fc/crypto/ripemd160.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/optional.hpp>
#include <graphene/chain/pts_address.hpp>
#include <bitcoin/bitcoin.hpp>
#include <graphene/crosschain_privatekey_management/util.hpp>
#include <assert.h>
#include <graphene/utilities/hash.hpp>
#include <list>
#include <libdevcore/DevCoreCommonJS.h>
#include <libdevcore/RLP.h>
#include <libdevcore/FixedHash.h>
#include <libethcore/TransactionBase.h>
namespace graphene { namespace privatekey_management {
	std::string BinToHex(const std::vector<char> &strBin, bool bIsUpper)
	{
		std::string strHex;
		strHex.resize(strBin.size() * 2);
		for (size_t i = 0; i < strBin.size(); i++)
		{
			uint8_t cTemp = strBin[i];
			for (size_t j = 0; j < 2; j++)
			{
				uint8_t cCur = (cTemp & 0x0f);
				if (cCur < 10)
				{
					cCur += '0';
				}
				else
				{
					cCur += ((bIsUpper ? 'A' : 'a') - 10);
				}
				strHex[2 * i + 1 - j] = cCur;
				cTemp >>= 4;
			}
		}

		return strHex;
	}


	crosschain_privatekey_base::crosschain_privatekey_base()
	{
		_key = fc::ecc::private_key();
	}

	crosschain_privatekey_base::crosschain_privatekey_base(fc::ecc::private_key& priv_key)
	{
		_key = priv_key;
	}

	fc::ecc::private_key  crosschain_privatekey_base::get_private_key()
	{
		FC_ASSERT(this->_key != fc::ecc::private_key(), "private key is empty!");
		
		return _key;
	}

	std::string  crosschain_privatekey_base::sign_trx(const std::string& raw_trx,int index)
	{
		//get endorsement
		libbitcoin::endorsement out;
		libbitcoin::wallet::ec_private libbitcoin_priv(get_wif_key());
		auto prev_script = libbitcoin::chain::script::to_pay_key_hash_pattern(libbitcoin_priv.to_payment_address().hash());
		libbitcoin::chain::script   libbitcoin_script;//(libbitcoin::data_chunk(base),true);	
		libbitcoin::chain::transaction  trx;
		trx.from_data(libbitcoin::config::base16(raw_trx));
		uint8_t hash_type = libbitcoin::machine::sighash_algorithm::all;

		auto result = libbitcoin::chain::script::create_endorsement(out, libbitcoin_priv.secret(), prev_script, trx, index, hash_type);
		assert( result == true);
// 		printf("endorsement is %s\n", libbitcoin::encode_base16(out).c_str());

		//get public hex
		libbitcoin::wallet::ec_public libbitcoin_pub = libbitcoin_priv.to_public();
		std::string pub_hex = libbitcoin_pub.encoded();
		//get signed raw-trx
		std::string endorsment_script = "[" + libbitcoin::encode_base16(out) + "]" + " [" + pub_hex + "] ";
// 		printf("endorsement script is %s\n", endorsment_script.c_str());
		libbitcoin_script.from_string(endorsment_script);

		//trx.from_data(libbitcoin::config::base16(raw_trx));
		trx.inputs()[index].set_script(libbitcoin_script);	    
		std::string signed_trx = libbitcoin::encode_base16(trx.to_data());
// 		printf("signed trx is %s\n", signed_trx.c_str());
		return signed_trx;
	}

	void crosschain_privatekey_base::generate(fc::optional<fc::ecc::private_key> k)
	{
		if (!k.valid())
		{

			_key = fc::ecc::private_key::generate();
		}
		else
		{
			_key = *k;
		}
	}

	std::string crosschain_privatekey_base::sign_message(const std::string& msg)
	{


		libbitcoin::wallet::message_signature sign;

		libbitcoin::wallet::ec_private libbitcoin_priv(get_wif_key());
		libbitcoin::data_chunk  data(msg.begin(), msg.end());

		libbitcoin::wallet::sign_message(sign, data, libbitcoin_priv.secret());

		auto result = libbitcoin::encode_base64(sign);
 		printf("the signed message is %s\n", result.c_str());
		return result;

	}
	bool crosschain_privatekey_base::validate_address(const std::string& addr, const bool is_new )
	{
		try {
			graphene::chain::pts_address pts(addr);
			return pts.is_valid() && (pts.version() == get_pubkey_prefix()|| pts.version() == get_script_prefix());
		}
		catch (fc::exception& e) {
			
		}
		try {
			graphene::chain::pts_address_p2wpkh pts(addr);
			return pts.is_valid();
		}
		catch (fc::exception& e) {

		}
		try {
			graphene::chain::pts_address_p2tr pts(addr,is_new);
			return pts.is_valid();
		}
		catch (fc::exception& e) {

		}

		return false;
		
	}
	bool crosschain_privatekey_base::validate_transaction(const std::string& addr,const std::string& redeemscript,const std::string& sig)
	{
		return graphene::utxo::validateUtxoTransaction(addr,redeemscript,sig);
	}
	fc::variant_object crosschain_privatekey_base::combine_trxs(const std::vector<std::string>& trxs)
	{
		auto trx = graphene::utxo::combine_trx(trxs);
		fc::mutable_variant_object result;
		result["trx"]=fc::json::from_string(graphene::utxo::decoderawtransaction(trx,get_pubkey_prefix(),get_script_prefix())).get_object();
		result["hex"] = trx;
		return result;
	}

	bool crosschain_privatekey_base::verify_message(const std::string addr, const std::string& content, const std::string& encript)
	{
		return true;
	}

	void btc_privatekey::init()
	{
		set_id(0);
		//set_pubkey_prefix(0x6F);
		//set_script_prefix(0xC4);
		//set_privkey_prefix(0xEF);
		set_pubkey_prefix(btc_pubkey);
		set_script_prefix(btc_script);
		set_privkey_prefix(btc_privkey);
	}



	std::string  btc_privatekey::get_wif_key()
	{	
		FC_ASSERT( is_empty() == false, "private key is empty!" );

		fc::sha256 secret = get_private_key().get_secret();
		//one byte for prefix, one byte for compressed sentinel
		const size_t size_of_data_to_hash = sizeof(secret) + 2;
		const size_t size_of_hash_bytes = 4;
		char data[size_of_data_to_hash + size_of_hash_bytes];
		data[0] = (char)get_privkey_prefix();
		memcpy(&data[1], (char*)&secret, sizeof(secret));
		data[size_of_data_to_hash - 1] = (char)0x01;
		fc::sha256 digest = fc::sha256::hash(data, size_of_data_to_hash);
		digest = fc::sha256::hash(digest);
		memcpy(data + size_of_data_to_hash, (char*)&digest, size_of_hash_bytes);
		return fc::to_base58(data, sizeof(data));
	
	}

    std::string   btc_privatekey::get_address()
    {
		FC_ASSERT(is_empty() == false, "private key is empty!");

        //configure for bitcoin
        uint8_t version = get_pubkey_prefix();
        bool compress = true;

		const fc::ecc::private_key& priv_key = get_private_key();
        fc::ecc::public_key  pub_key = priv_key.get_public_key();

        graphene::chain::pts_address btc_addr(pub_key, compress, version);
		std::string  addr = btc_addr.operator fc::string();

		return addr;
    }
	std::string btc_privatekey::get_address_by_pubkey(const std::string& pub)
	{
		return graphene::privatekey_management::get_address_by_pubkey(pub, get_pubkey_prefix());
	}
	std::string btc_privatekey::get_public_key()
	{
		libbitcoin::wallet::ec_private libbitcoin_priv(get_wif_key());

		libbitcoin::wallet::ec_public libbitcoin_pub = libbitcoin_priv.to_public();
		std::string pub_hex = libbitcoin_pub.encoded();

		return pub_hex;

	}

	std::string btc_privatekey::sign_message(const std::string& msg)
	{
		return this->crosschain_privatekey_base::sign_message(msg);
	}
	std::string btc_privatekey::sign_trx(const std::string& raw_trx,int index)
	{
		return this->crosschain_privatekey_base::sign_trx(raw_trx,index);
	}

	fc::optional<fc::ecc::private_key>   btc_privatekey::import_private_key(const std::string& wif_key)
	{
		auto key = graphene::utilities::wif_to_key(wif_key);
		set_key(*key);
		return key;

	}
	std::string btc_privatekey::mutisign_trx( const std::string& redeemscript, const fc::variant_object& raw_trx)
	{
		try {
			FC_ASSERT(raw_trx.contains("hex"));
			FC_ASSERT(raw_trx.contains("trx"));
			auto tx = raw_trx["trx"].get_object();
			auto size = tx["vin"].get_array().size();
			std::string trx = raw_trx["hex"].as_string();
			for (int index = 0; index < size; index++)
			{
				auto endorse = graphene::privatekey_management::create_endorsement(get_wif_key(), redeemscript,trx,index);
				trx = graphene::privatekey_management::mutisign_trx(endorse,redeemscript,trx,index);
			}
			return trx;
		}FC_CAPTURE_AND_RETHROW((redeemscript)(raw_trx));
	}


	static libbitcoin::chain::script strip_code_seperators(const libbitcoin::chain::script& script_code)
	{
		libbitcoin::machine::operation::list ops;

		for (auto op = script_code.begin(); op != script_code.end(); ++op)
			if (op->code() != libbitcoin::machine::opcode::codeseparator)
				ops.push_back(*op);

		return libbitcoin::chain::script(std::move(ops));
	}
	void input_todata(libbitcoin::istream_reader& source, libbitcoin::ostream_writer& write) {
		auto InputCount = source.read_size_little_endian();
		write.write_size_little_endian(uint64_t(InputCount));
		//std::cout << InputCount << std::endl;
		for (uint64_t i = 0; i < InputCount; ++i) {
			auto Hash = source.read_hash();
			auto Index = source.read_4_bytes_little_endian();
			auto Tree = source.read_size_little_endian();
			write.write_hash(Hash);
			write.write_4_bytes_little_endian(Index);
			write.write_size_little_endian(Tree);
			auto Sequence = source.read_4_bytes_little_endian();
			write.write_4_bytes_little_endian(Sequence);
		}
	}
	void output_todata(libbitcoin::istream_reader& source, libbitcoin::ostream_writer& write) {
		auto OutputCount = source.read_size_little_endian();
		write.write_size_little_endian((uint64_t)OutputCount);
		//std::cout << (uint64_t)OutputCount << std::endl;
		for (uint64_t i = 0; i < OutputCount; ++i) {
			auto Value = source.read_8_bytes_little_endian();
			auto Version = source.read_2_bytes_little_endian();
			auto output_count = source.read_size_little_endian();
			auto PkScript = source.read_bytes(output_count);
			write.write_8_bytes_little_endian(Value);
			write.write_2_bytes_little_endian(Version);
			write.write_size_little_endian(output_count);
			write.write_bytes(PkScript);
			//std::cout << PkScript.size() << "-" << output_count<<std::endl;
		}
	}
	void witness_todata(libbitcoin::istream_reader& source, libbitcoin::ostream_writer& write, libbitcoin::chain::script libbitcoin_script,int vin_index,bool bHashMode = false) {
		auto witness_count = source.read_size_little_endian();
		write.write_size_little_endian((uint64_t)witness_count);
		for (uint64_t i = 0; i < (int)witness_count; ++i) {
			auto ValueIn = source.read_8_bytes_little_endian();
			auto BlockHeight = source.read_4_bytes_little_endian();
			auto BlockIndex = source.read_4_bytes_little_endian();
			auto signtureCount = source.read_size_little_endian();
			//std::cout << signtureCount << std::endl;
			auto SignatureScript = source.read_bytes(signtureCount);
			if (!bHashMode){
				write.write_8_bytes_little_endian(ValueIn);
				write.write_4_bytes_little_endian(BlockHeight);
				write.write_4_bytes_little_endian(BlockIndex);
			}
			//std::cout << SignatureScript.size() << "-" << signtureCount << std::endl;
			if (i == vin_index) {
				write.write_size_little_endian(libbitcoin_script.to_data(false).size());
				write.write_bytes(libbitcoin_script.to_data(false));
			}
			else {
				if (bHashMode){
					write.write_size_little_endian((uint8_t)0);
				}
				else {
					write.write_size_little_endian(signtureCount);
					write.write_bytes(SignatureScript);
				}
				
			}

		}
	}
	bool  from_hex(const char *pSrc, std::vector<char> &pDst, unsigned int nSrcLength, unsigned int &nDstLength)
	{
		if (pSrc == 0)
		{
			return false;
		}

		nDstLength = 0;

		if (pSrc[0] == 0) // nothing to convert  
			return 0;

		// 计算需要转换的字节数  
		for (int j = 0; pSrc[j]; j++)
		{
			if (isxdigit(pSrc[j]))
				nDstLength++;
		}

		// 判断待转换字节数是否为奇数，然后加一  
		if (nDstLength & 0x01) nDstLength++;
		nDstLength /= 2;

		if (nDstLength > nSrcLength)
			return false;

		nDstLength = 0;

		int phase = 0;
		char temp_char;

		for (int i = 0; pSrc[i]; i++)
		{
			if (!isxdigit(pSrc[i]))
				continue;

			unsigned char val = pSrc[i] - (isdigit(pSrc[i]) ? 0x30 : (isupper(pSrc[i]) ? 0x37 : 0x57));

			if (phase == 0)
			{
				temp_char = val << 4;
				phase++;
			}
			else
			{
				temp_char |= val;
				phase = 0;
				pDst.push_back(temp_char);
				nDstLength++;
			}
		}

		return true;
	}
	
	
	crosschain_management::crosschain_management()
	{
		crosschain_decode.insert(std::make_pair("BTC", &graphene::privatekey_management::btc_privatekey::decoderawtransaction));
		
		
	}
	crosschain_privatekey_base * crosschain_management::get_crosschain_prk(const std::string& name)
	{
		auto itr = crosschain_prks.find(name);
		if (itr != crosschain_prks.end())
		{
			return itr->second;
		}

		if (name == "BTC")
		{
			auto itr = crosschain_prks.insert(std::make_pair(name, new btc_privatekey()));
			return itr.first->second;
		}
		
		return nullptr;
	}

	fc::variant_object crosschain_management::decoderawtransaction(const std::string& raw_trx, const std::string& symbol)
	{
		try {
			std::string temp_symbol = symbol;
			if (symbol.find("OriginalERC") != symbol.npos)
			{
				temp_symbol = "OriginalERC";
			}
			auto iter = crosschain_decode.find(temp_symbol);
			FC_ASSERT(iter != crosschain_decode.end(), "plugin not exist.");
			return iter->second(raw_trx);
		}FC_CAPTURE_AND_RETHROW((raw_trx)(symbol))
	}


} } // end namespace graphene::privatekey_management
