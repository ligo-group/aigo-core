﻿/**
* Author: wengqiang (email: wens.wq@gmail.com  site: qiangweng.site)
*
* Copyright © 2015--2018 . All rights reserved.
*
* File: private_key.hpp
* Date: 2018-01-11
*/

#pragma once

#include <fc/crypto/elliptic.hpp>
#include <string>
#include "Keccak.hpp"
#include <fc/variant_object.hpp>
#include <fc/io/json.hpp>
//const int btc_pubkey = 0x6f;
//const int btc_script = 0xC4;
//const int btc_privkey = 0x80;
const int btc_pubkey = 0x00;
const int btc_script = 0x05;
const int btc_privkey = 0x80;




namespace graphene {
	namespace privatekey_management {

		#define COMMAND_BUF  1024

		class crosschain_privatekey_base
		{
		public:

			crosschain_privatekey_base();
			crosschain_privatekey_base(fc::ecc::private_key& priv_key);
			virtual std::string  sign_trx(const std::string& raw_trx,int index);
			virtual std::string  sign_message(const std::string& msg);
			virtual bool verify_message(const std::string addr, const std::string& content, const std::string& encript);
			fc::ecc::private_key  get_private_key();

			virtual std::string get_wif_key() = 0;
			virtual std::string get_address() = 0;
			virtual fc::optional<fc::ecc::private_key>  import_private_key(const std::string& wif_key) = 0;
			void generate(fc::optional<fc::ecc::private_key> k= fc::optional<fc::ecc::private_key>());
			bool is_empty() const { return _key == fc::ecc::private_key(); }
			virtual std::string get_public_key() = 0;
			virtual std::string get_address_by_pubkey(const std::string& pub) = 0;
			virtual bool validate_transaction(const std::string& addr,const std::string& redeemscript,const std::string& sig) ;
			int  get_pubkey_prefix() { return _pubkey_prefix; }
			bool set_pubkey_prefix(int prefix = 0) { _pubkey_prefix = prefix; return true; }
			bool set_script_prefix(int prefix = 0) { _script_prefix = prefix; return true; }
			int get_script_prefix() { return _script_prefix; }
			virtual std::string mutisign_trx(const std::string& redeemscript, const fc::variant_object& raw_trx) =0;
			virtual fc::variant_object combine_trxs(const std::vector<std::string>& trxs) ;
			int get_privkey_prefix() { return _privkey_prefix; }
			bool set_privkey_prefix(int prefix = 0)	{ _privkey_prefix = prefix; return true; }
			void set_key(fc::ecc::private_key& key) { _key = key; }
			int		get_id() { return _id; }
			bool	set_id(int p_id) { _id = p_id; return true; }
			virtual bool validate_address(const std::string& addr, const bool is_new = false) ;
			fc::ecc::private_key  _key;

			int                   _id;
			int                   _pubkey_prefix;
			int                   _script_prefix;
			int					  _privkey_prefix;


		};


		class btc_privatekey : public crosschain_privatekey_base
		{
		public:
			btc_privatekey() { init(); };
			btc_privatekey(fc::ecc::private_key& priv_key) : crosschain_privatekey_base(priv_key) { init(); };
				                                                     

			virtual std::string get_wif_key() ;
			virtual std::string get_address() ;
			virtual std::string get_public_key();
			virtual std::string  sign_message(const std::string& msg);
			virtual std::string get_address_by_pubkey(const std::string& pub);
			virtual std::string mutisign_trx(const std::string& redeemscript, const fc::variant_object& raw_trx);
			virtual fc::optional<fc::ecc::private_key>  import_private_key(const std::string& wif_key) ;
			static  fc::variant_object  decoderawtransaction(const std::string& trx);
			virtual std::string  sign_trx(const std::string& raw_trx,int index);
		private:
			void init();

		};



		
		typedef fc::variant_object(*FuncPtr)(const std::string& trx);
		class crosschain_management
		{
		public:
			crosschain_management();
			~crosschain_management() {}
			static crosschain_management& get_instance()
			{
				static crosschain_management mgr;
				return mgr;
			}
			crosschain_privatekey_base * get_crosschain_prk(const std::string& name);
			fc::variant_object decoderawtransaction(const std::string& raw_trx, const std::string& symbol);
		private:
			std::map<std::string, crosschain_privatekey_base *> crosschain_prks;
			std::map<std::string, FuncPtr> crosschain_decode;
		};
	}
} // end namespace graphene::privatekey_management


FC_REFLECT(graphene::privatekey_management::crosschain_privatekey_base,
	       (_key)
		   (_id)
	       (_pubkey_prefix)
	       (_privkey_prefix)
		  )
