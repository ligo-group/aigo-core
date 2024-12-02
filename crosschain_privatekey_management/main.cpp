/**
* Author: wengqiang (email: wens.wq@gmail.com  site: qiangweng.site)
*
* Copyright © 2015--2018 . All rights reserved.
*
* File: main.cpp
* Date: 2018-01-11
*/

#include <graphene/crosschain_privatekey_management/private_key.hpp>
#include <graphene/crosschain_privatekey_management/database_privatekey.hpp>
#include "fc/crypto/base58.hpp"
#include <bitcoin/bitcoin.hpp>
#include <graphene/crosschain_privatekey_management/util.hpp>
#include <graphene/chain/protocol/address.hpp>
#include <graphene/chain/protocol/types.hpp>
#include <graphene/utilities/key_conversion.hpp>
#include <fc/crypto/elliptic.hpp>
#include <string> 
#include <vector> 
#include <iostream>

#include <fc/thread/thread.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/crypto/aes.hpp>
#include <graphene/wallet/wallet.hpp>
#include <algorithm>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>


int main(int argc, char** argv)
{
	using namespace graphene::privatekey_management;
	

auto addr =graphene::privatekey_management::get_address_by_pubkey("0406CCAE7536386DA2C5ADD428B099C7658814CA837F94FADE365D0EC6B1519385FF83EC5F2C0C8F016A32134589F7B9E97ACBFEFD2EF12A91FA622B38A1449EEB", 0);
std::cout << addr << std::endl;
boost::uuids::uuid uid = boost::uuids::random_generator()();

vector<int> vec(uid.begin(),uid.begin()+2);


for (int i : vec)
{
	std::cout << i;
}
std::cout <<std::endl;


getchar();
	return 0;
}



