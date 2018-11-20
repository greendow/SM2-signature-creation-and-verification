/**************************************************
* File name: sm2_create_key_pair.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 18th, 2018
* Description: implement SM2 key pair creation function
**************************************************/

#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "sm2_cipher_error_codes.h"
#include "sm2_create_key_pair.h"

/*********************************************************/
int sm2_create_key_pair(SM2_KEY_PAIR *key_pair)
{
	int error_code;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_d = NULL, *bn_x = NULL, *bn_y = NULL;
	const BIGNUM *bn_order;
	EC_GROUP *group = NULL;
	EC_POINT *ec_pt = NULL;
	unsigned char pub_key_x[32], pub_key_y[32];

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(ctx = BN_CTX_secure_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_y = BN_CTX_get(ctx);
	if ( !(bn_y) )
	{
	   goto clean_up;
	}

	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
	   goto clean_up;
	}
	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
	   goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
	   goto clean_up;
	}

	error_code = CREATE_SM2_KEY_PAIR_FAIL;
	do
	{
	   if ( !(BN_rand_range(bn_d, bn_order)) )
	   {
	      goto clean_up;
	   }	
	} while ( BN_is_zero(bn_d) );

	if ( !(EC_POINT_mul(group, ec_pt, bn_d, NULL, NULL, ctx)) )
	{
	   goto clean_up;
	}
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           ec_pt,
						   bn_x,
						   bn_y,
						   ctx)) )
	{
	   goto clean_up;
	}	

	if ( BN_bn2binpad(bn_d,
	                  key_pair->pri_key,
			  sizeof(key_pair->pri_key)) != sizeof(key_pair->pri_key) )
	{
	   goto clean_up;
	}
	if ( BN_bn2binpad(bn_x,
	                  pub_key_x,
			  sizeof(pub_key_x)) != sizeof(pub_key_x) )
	{
	   goto clean_up;
	}
	if ( BN_bn2binpad(bn_y,
	                  pub_key_y,
			  sizeof(pub_key_y)) != sizeof(pub_key_y) )
	{
	   goto clean_up;
	}

	key_pair->pub_key[0] = 0x4;
	memcpy((key_pair->pub_key + 1), pub_key_x, sizeof(pub_key_x));
	memcpy((key_pair->pub_key + 1 + sizeof(pub_key_x)), pub_key_y, sizeof(pub_key_y));
	error_code = 0;
	
clean_up:
    if (ctx)
	{
	   BN_CTX_end(ctx);
	   BN_CTX_free(ctx);
	}
	
	if (group)
	{
	   EC_GROUP_free(group);
	}

	if (ec_pt)
	{
	   EC_POINT_free(ec_pt);
	}

	return error_code;
}
