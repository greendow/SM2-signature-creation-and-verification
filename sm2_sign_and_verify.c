/**************************************************
* File name: sm2_sign_and_verify.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 19th, 2018
* Description: implement SM2 sign data and verify
    signature functions
**************************************************/

#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "sm2_cipher_error_codes.h"
#include "sm3_with_preprocess.h"
#include "sm2_sign_and_verify.h"

/*********************************************************/
int sm2_sign_data_test(const unsigned char *message,
	               const int message_len,
		       const unsigned char *id,
		       const int id_len,
		       const unsigned char *pub_key,
		       const unsigned char *pri_key,
		       SM2_SIGNATURE_STRUCT *sm2_sig)
{
	int error_code;
	unsigned char digest[32];
	BN_CTX *ctx = NULL;
	BIGNUM *bn_e = NULL, *bn_k = NULL, *bn_x = NULL, *bn_tmp = NULL;
	BIGNUM *bn_r = NULL, *bn_s = NULL, *bn_one = NULL, *bn_d = NULL;
	BIGNUM *bn_sum_inv=NULL, *bn_dif=NULL;
	const BIGNUM *bn_order;
	EC_GROUP *group = NULL;
	const EC_POINT *generator;
	EC_POINT *k_G = NULL;
	unsigned char k[32] = {0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a,
	                       0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0, 0x2d, 0xcc,
	                       0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce,
	                       0x6d, 0x54, 0xb8, 0x0d, 0xea, 0xc1, 0xbc, 0x21};

	if ( error_code = sm3_digest_with_preprocess(message,
	                                             message_len,
						     id,
						     id_len,
						     pub_key,
						     digest) )
	{
	   return error_code;
	}

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(ctx = BN_CTX_secure_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_one = BN_CTX_get(ctx);
	bn_e = BN_CTX_get(ctx);
	bn_k = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_tmp = BN_CTX_get(ctx);
	bn_r = BN_CTX_get(ctx);
	bn_s = BN_CTX_get(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_sum_inv = BN_CTX_get(ctx);
	bn_dif = BN_CTX_get(ctx);
	if ( !(bn_dif) )
	{
	   goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
	   goto clean_up;
	}

	if ( !(k_G = EC_POINT_new(group)) )
	{
	   goto clean_up;
	}

	error_code = COMPUTE_SM2_SIGNATURE_FAIL;
	if ( !(BN_one(bn_one)) )
	{
	   goto clean_up;
	}

	if ( !(BN_bin2bn(pri_key, 32, bn_d)) )
	{
	   goto clean_up;
	}

	if ( !(BN_bin2bn(digest, sizeof(digest), bn_e)) )
	{
	   goto clean_up;
	}
	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
	   goto clean_up;
	}
	if ( !(generator = EC_GROUP_get0_generator(group)) )
	{
	   goto clean_up;
	}
	
	do
	{
		if ( !(BN_bin2bn(k, sizeof(k), bn_k)) )
		{
		   goto clean_up;
		}
		if ( BN_is_zero(bn_k) )
		{
		   continue;
		}
		if ( !(EC_POINT_mul(group, k_G, bn_k, NULL, NULL, ctx)) )
		{
		   goto clean_up;
		}
		if ( !(EC_POINT_get_affine_coordinates_GFp(group,
		                                           k_G,
							   bn_x,
							   bn_tmp,
							   ctx)) )
		{
		   goto clean_up;
		}
		if ( !(BN_mod_add(bn_r, bn_e, bn_x, bn_order, ctx)) )
		{
		   goto clean_up;
		}
		if ( BN_is_zero(bn_r) ) /* check if r == 0 ? */
		{
		   continue;
		}
		if ( !(BN_add(bn_tmp, bn_r, bn_k)) )
		{
		   goto clean_up;
		}
		if ( !(BN_cmp(bn_tmp, bn_order)) )  /* check if (r + k) == n ? */
		{
		   continue;
		}
		if ( !(BN_add(bn_tmp, bn_one, bn_d)) )  /* compute (1 + d) */
		{
		   goto clean_up;
		}
		if ( !(BN_mod_inverse(bn_sum_inv, bn_tmp, bn_order, ctx)) )
		{
		   goto clean_up;
		}
		if ( !(BN_mul(bn_tmp, bn_r, bn_d, ctx)) )
		{
		   goto clean_up;
		}
		if ( !(BN_mod_sub(bn_dif, bn_k, bn_tmp, bn_order, ctx)) )
		{
		   goto clean_up;
		}
		if ( !(BN_mod_mul(bn_s, bn_sum_inv, bn_dif, bn_order, ctx)) )
		{
		   goto clean_up;
		}
	} while ( BN_is_zero(bn_s) );  /* check if s == 0 ? */
	
	if ( BN_bn2binpad(bn_r,
	                  sm2_sig->r_coordinate,
			  sizeof(sm2_sig->r_coordinate)) != sizeof(sm2_sig->r_coordinate) )
	{
	   goto clean_up;
	}
	if ( BN_bn2binpad(bn_s,
	                  sm2_sig->s_coordinate,
			  sizeof(sm2_sig->s_coordinate)) != sizeof(sm2_sig->s_coordinate) )
	{
	   goto clean_up;
	}
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
	if (k_G)
	{
	   EC_POINT_free(k_G);
	}

	return error_code;
}

/*********************************************************/
int sm2_sign_data(const unsigned char *message,
                  const int message_len,
		  const unsigned char *id,
		  const int id_len,
		  const unsigned char *pub_key,
		  const unsigned char *pri_key,
		  SM2_SIGNATURE_STRUCT *sm2_sig)
{
	int error_code;
	unsigned char digest[32];
	BN_CTX *ctx = NULL;
	BIGNUM *bn_e = NULL, *bn_k = NULL, *bn_x = NULL, *bn_tmp = NULL;
	BIGNUM *bn_r = NULL, *bn_s = NULL, *bn_one = NULL, *bn_d = NULL;
	BIGNUM *bn_sum_inv=NULL, *bn_dif=NULL;
	const BIGNUM *bn_order;
	EC_GROUP *group = NULL;
	const EC_POINT *generator;
	EC_POINT *k_G = NULL;

	if ( error_code = sm3_digest_with_preprocess(message,
	                                             message_len,
						     id,
						     id_len,
						     pub_key,
						     digest) )
	{
	   return error_code;
	}

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(ctx = BN_CTX_secure_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_one = BN_CTX_get(ctx);
	bn_e = BN_CTX_get(ctx);
	bn_k = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_tmp = BN_CTX_get(ctx);
	bn_r = BN_CTX_get(ctx);
	bn_s = BN_CTX_get(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_sum_inv = BN_CTX_get(ctx);
	bn_dif = BN_CTX_get(ctx);
	if ( !(bn_dif) )
	{
	   goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
	   goto clean_up;
	}

	if ( !(k_G = EC_POINT_new(group)) )
	{
	   goto clean_up;
	}

	error_code = COMPUTE_SM2_SIGNATURE_FAIL;
	if ( !(BN_one(bn_one)) )
	{
	   goto clean_up;
	}

	if ( !(BN_bin2bn(pri_key, 32, bn_d)) )
	{
	   goto clean_up;
	}

	if ( !(BN_bin2bn(digest, sizeof(digest), bn_e)) )
	{
	   goto clean_up;
	}
	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
	   goto clean_up;
	}
	if ( !(generator = EC_GROUP_get0_generator(group)) )
	{
	   goto clean_up;
	}
	
	do
	{
		if ( !(BN_rand_range(bn_k, bn_order)) )
		{
		   goto clean_up;
		}
		if ( BN_is_zero(bn_k) )
		{
		   continue;
		}
		if ( !(EC_POINT_mul(group, k_G, bn_k, NULL, NULL, ctx)) )
		{
		   goto clean_up;
		}
		if ( !(EC_POINT_get_affine_coordinates_GFp(group,
		                                           k_G,
							   bn_x,
							   bn_tmp,
							   ctx)) )
		{
		   goto clean_up;
		}
		if ( !(BN_mod_add(bn_r, bn_e, bn_x, bn_order, ctx)) )
		{
		   goto clean_up;
		}
		if ( BN_is_zero(bn_r) ) /* check if r==0 ? */
		{
		   continue;
		}
		if ( !(BN_add(bn_tmp, bn_r, bn_k)) )
		{
		   goto clean_up;
		}
		if ( !(BN_cmp(bn_tmp, bn_order)) )  /* check if (r + k) == n ? */
		{
			continue;
		}
		if ( !(BN_add(bn_tmp, bn_one, bn_d)) )  /* compute (1 + d) */
		{
		   goto clean_up;
		}
		if ( !(BN_mod_inverse(bn_sum_inv, bn_tmp, bn_order, ctx)) )
		{
		   goto clean_up;
		}
		if ( !(BN_mul(bn_tmp, bn_r, bn_d, ctx)) )
		{
		   goto clean_up;
		}
		if ( !(BN_mod_sub(bn_dif, bn_k, bn_tmp, bn_order, ctx)) )
		{
		   goto clean_up;
		}
		if ( !(BN_mod_mul(bn_s, bn_sum_inv, bn_dif, bn_order, ctx)) )
		{
		   goto clean_up;
		}
	} while ( BN_is_zero(bn_s) );  /* check if s == 0 ? */
	
	if ( BN_bn2binpad(bn_r,
	                  sm2_sig->r_coordinate,
			  sizeof(sm2_sig->r_coordinate)) != sizeof(sm2_sig->r_coordinate) )
	{
	   goto clean_up;
	}
	if ( BN_bn2binpad(bn_s,
	                  sm2_sig->s_coordinate,
			  sizeof(sm2_sig->s_coordinate)) != sizeof(sm2_sig->s_coordinate) )
	{
	   goto clean_up;
	}
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
	if (k_G)
	{
	   EC_POINT_free(k_G);
	}

	return error_code;
}

/*********************************************************/
int sm2_verify_sig(const unsigned char *message,
                   const int message_len,
		   const unsigned char *id,
		   const int id_len,
		   const unsigned char *pub_key,
		   SM2_SIGNATURE_STRUCT *sm2_sig)
{
	int error_code;
	unsigned char digest[32];
	unsigned char pub_key_x[32], pub_key_y[32];
	BN_CTX *ctx = NULL;
	BIGNUM *bn_e = NULL, *bn_r = NULL, *bn_s = NULL, *bn_t = NULL;
	BIGNUM *bn_pub_key_x = NULL, *bn_pub_key_y = NULL;
	BIGNUM *bn_x = NULL, *bn_y = NULL, *bn_R = NULL;
	const BIGNUM *bn_order;
	EC_GROUP *group = NULL;
	const EC_POINT *generator;
	EC_POINT *ec_pub_key_pt = NULL, *ec_pt1 = NULL, *ec_pt2 = NULL;

	if ( error_code = sm3_digest_with_preprocess(message,
	                                             message_len,
						     id,
						     id_len,
						     pub_key,
						     digest) )
	{
	   return error_code;
	}

	memcpy(pub_key_x, (pub_key + 1), sizeof(pub_key_x));
	memcpy(pub_key_y, (pub_key + 1 + sizeof(pub_key_x)), sizeof(pub_key_y));

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(ctx = BN_CTX_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_e = BN_CTX_get(ctx);
	bn_r = BN_CTX_get(ctx);
	bn_s = BN_CTX_get(ctx);
	bn_t = BN_CTX_get(ctx);
	bn_pub_key_x = BN_CTX_get(ctx);
	bn_pub_key_y = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);	
	bn_y = BN_CTX_get(ctx);
	bn_R = BN_CTX_get(ctx);
	if ( !(bn_R) )
	{
	   goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
	   goto clean_up;
	}
	
	if ( !(ec_pub_key_pt = EC_POINT_new(group)) )
	{
	   goto clean_up;
	}
	if ( !(ec_pt1 = EC_POINT_new(group)) )
	{
	   goto clean_up;
	}
	if ( !(ec_pt2 = EC_POINT_new(group)) )
	{
	   goto clean_up;
	}

	error_code = VERIFY_SM2_SIGNATURE_FAIL;
	if ( !(BN_bin2bn(digest, sizeof(digest), bn_e)) )
	{
	   goto clean_up;
	}
	if ( !(BN_bin2bn(sm2_sig->r_coordinate, sizeof(sm2_sig->r_coordinate), bn_r)) )
	{
	   goto clean_up;
	}
	if ( !(BN_bin2bn(sm2_sig->s_coordinate, sizeof(sm2_sig->s_coordinate), bn_s)) )
	{
	   goto clean_up;
	}
	if ( !(BN_bin2bn(pub_key_x, sizeof(pub_key_x), bn_pub_key_x)) )
	{
	   goto clean_up;
	}
	if ( !(BN_bin2bn(pub_key_y, sizeof(pub_key_y), bn_pub_key_y)) )
	{
	   goto clean_up;
	}

	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
	   goto clean_up;
	}
	if ( !(generator = EC_GROUP_get0_generator(group)) )
	{
	   goto clean_up;
	}

	if ( (BN_is_zero(bn_r)) || (BN_cmp(bn_r, bn_order) != (-1)) )
	{
	   error_code = INVALID_SM2_SIGNATURE;
	   goto clean_up;
	}
	if ( (BN_is_zero(bn_s)) || (BN_cmp(bn_s, bn_order) != (-1)) )
	{
	   error_code = INVALID_SM2_SIGNATURE;
	   goto clean_up;
	}

	if ( !(BN_mod_add(bn_t, bn_r, bn_s, bn_order, ctx)) )
	{
	   goto clean_up;
	}
	if ( BN_is_zero(bn_t) )
	{
	   goto clean_up;
	}
	
	if ( !(EC_POINT_mul(group, ec_pt1, bn_s, NULL, NULL, ctx)) )
	{
	   goto clean_up;
	}
	
	if ( !(EC_POINT_set_affine_coordinates_GFp(group,
	                                           ec_pub_key_pt,
						   bn_pub_key_x,
						   bn_pub_key_y,
						   ctx)) )
	{
	   goto clean_up;
	}
	
	if ( !(EC_POINT_mul(group, ec_pt2, NULL, ec_pub_key_pt, bn_t, ctx)) )
	{
	   goto clean_up;
	}
	
	if ( !(EC_POINT_add(group, ec_pt1, ec_pt1, ec_pt2, ctx)) )
	{
	   goto clean_up;
	}
	
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           ec_pt1,
						   bn_x,
						   bn_y,
						   ctx)) )
	{
	   goto clean_up;
	}
	if ( !(BN_mod_add(bn_R, bn_e, bn_x, bn_order, ctx)) )
	{
	   goto clean_up;
	}
	
	if ( !(BN_cmp(bn_r, bn_R)) ) /* verify signature succeed */
	{
	   error_code = 0;
	}

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

	if (ec_pub_key_pt)
	{
	   EC_POINT_free(ec_pub_key_pt);
	}
	if (ec_pt1)
	{
	   EC_POINT_free(ec_pt1);
	}
	if (ec_pt2)
	{
	   EC_POINT_free(ec_pt2);
	}

	return error_code;
}
