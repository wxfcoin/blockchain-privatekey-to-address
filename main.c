#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eoskeys.h"
#include "eth.h"
#include "etherkeys.h"
#include "bitcoinkeys.h"
#include "bip39.h"
#include "bip32.h"
#include "bignum256.h"
#include "bch.h"

int test_all(){
	//0、bchaddress test
	btc_to_bch("12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
	
	//1、eth methodId
	char * method_code = (char*)"transfer(address,uint256)";
	char method_id[11] = { 0 };
	get_method_id(method_code, OUT method_id);
	printf("method:%s, methodId:%s\n", method_code, method_id);

	//2、eos address
	const char *priv = "618c79503a3d1476211c8be7876e94e8723596a1e0b0204c050229983c9bfebd";
	priv = "0000000000000000000000000000000000000000000000000000000000000000";
	priv = "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a";
	char privStr[256] = "PRIV";
	char addrStr[256] = "ADDR";

	eosPrivate2Address(priv, privStr, addrStr);
	printf("private key(%d): %s\n", strlen(priv),priv);
	printf("private key coded: %s\n", privStr);
	printf("eos address: EOS%s\n", addrStr);

	//3、eth address
	char ethAddrStr[43] = { 0 };
	etherPrivate2Address(priv, ethAddrStr);
	printf("eth address: %s\n", ethAddrStr);

	//4、bitcoin address
	char bitcoinAddr[35] = { 0 };
	bitcoinPrivate2Address(priv, "", bitcoinAddr, 0, true);
	printf("bitcoin address:%s\n", bitcoinAddr);

	//5、bip39
	const char* words = mnemonic_generate(128, NULL);
	printf("generat mnemonic:%s\n",words);

	uint8_t seed[64];
	mnemonic_to_seed(words, "123456", seed, NULL);

	//6、bip32
	HDNode hd;
	hdnode_from_seed(seed, 64, &hd);

	char private_key_hex[67] = {0}, public_key_hex[67] = { 0 };
	bigToHexString(hd.private_key, private_key_hex);
	bigToHexString(hd.public_key, public_key_hex);
	printf("root private key:%s,root public key:%s\n", private_key_hex, public_key_hex);

	for (int i = 0; i < 10; ++i)
	{
		hdnode_private_ckd(&hd, i);
		char private_key_hex[67] = { 0 }, public_key_hex[67] = { 0 };
		bigToHexString(hd.private_key, private_key_hex);
		bigToHexString(hd.public_key, public_key_hex);
		printf("[%d] private key:%s,public key:%s\n", i, private_key_hex, public_key_hex);
	}
	
	return 0;
}

void test_ecdsa(const char* privIn);
int main() {
	const char* priv;
	priv = "618c79503a3d1476211c8be7876e94e8723596a1e0b0204c050229983c9bfebd";		//
	priv = "0000000000000000000000000000000000000000000000000000000000000000";		//15wJjXvfQzo3SXqoWGbWZmNYND1Si4siqV	16QaFeudRUt8NYy2yzjm3BMvG4xBbAsBFM	
	//priv = "0000000000000000000000000000000000000000000000000000000000000001";	//1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH	1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
	//priv = "0000000000000000000000000000000000000000000000000000000000000002";	//	1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m
	// 
	//priv = "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a";	// addr:1K5xEGHYwNmp2hReF3h7kpEbK2NsGAfGsK
	priv = "fadbd76ee76c73e3648cc0115ab7dba06d075e658a6890060424d2ba89849dce";
//随机公钥Hex: 04dc1dca5d699f6711b1dedccd6a99526a592deeba2b19662e8bf49c0f624026e1a1ed708cd083f6006b230086da1cfecf3534fa20da8da6b00a234341c83c9a55
//对应私钥Hex : 7437401de6c377defb753b5b31a2004c46766d60d2831dda34df7542ff14b838
	priv = "7437401de6c377defb753b5b31a2004c46766d60d2831dda34df7542ff14b838";
	//4、bitcoin address
	char bitcoinAddr[35] = { 0 };
	bitcoinPrivate2Address(priv, "", bitcoinAddr, 1, false);
	printf("bitcoin address: %s\n", bitcoinAddr);		//compressed bitcoin address
	bitcoinPrivate2Address(priv, "", bitcoinAddr, 1, true);
	printf("compressd address: %s\n", bitcoinAddr);		//compressed bitcoin address
	test_ecdsa(priv);
	//5、bip39
	//char key[32] = { 0 };
	//const char* words = mnemonic_generate(128, key);
	//printf("generat mnemonic:%s\n", words);
	return 0;
}
