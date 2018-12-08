/**************************************************
* File name: sm2_sign_and_verify.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 19th, 2018
* Description: declare SM2 sign data and verify
    signature functions
**************************************************/

#ifndef HEADER_SM2_SIGN_AND_VERIFY_COMPUTATION_H
  #define HEADER_SM2_SIGN_AND_VERIFY_COMPUTATION_H

typedef struct sm2_sig_structure {
	unsigned char r_coordinate[32];
	unsigned char s_coordinate[32];
} SM2_SIGNATURE_STRUCT;

#ifdef  __cplusplus
  extern "C" {
#endif

/**************************************************
* Name: sm2_sign_data_test
* Function: compute SM2 signature with a fixed internal 
    random number k given in GM/T 0003.5-2012
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    pri_key[in]      SM2 private key
    sm2_sig[out]     SM2 signature
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. This function is only used for testing! When a 
   signature is created by invoking this function,
   a fixed random number value k is used. The random
   number value is given in GM/T 0003.5-2012.
2. The user id value cannot be NULL. If the specific 
   value is unknown, the default user id "1234567812345678" 
   can be used.
3. "pub_key" is a octet string of 65 byte length. It 
   is a concatenation of 04 || X || Y. X and Y both are 
   SM2 public key coordinates of 32-byte length.
4. "pri_key" is a octet string of 32 byte length.
**************************************************/
int sm2_sign_data_test(const unsigned char *message,
	               const int message_len,
		       const unsigned char *id,
		       const int id_len,
		       const unsigned char *pub_key,
		       const unsigned char *pri_key,
		       SM2_SIGNATURE_STRUCT *sm2_sig);

/**************************************************
* Name: sm2_sign_data
* Function: compute SM2 signature
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    pri_key[in]      SM2 private key
    sm2_sig[out]     SM2 signature
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. The user id value cannot be NULL. If the specific 
   value is unknown, the default user id "1234567812345678" 
   can be used.
2. "pub_key" is a octet string of 65 byte length. It 
   is a concatenation of 04 || X || Y. X and Y both are 
   SM2 public key coordinates of 32-byte length.
3. "pri_key" is a octet string of 32 byte length.
**************************************************/
int sm2_sign_data(const unsigned char *message,
                  const int message_len,
		  const unsigned char *id,
		  const int id_len,
		  const unsigned char *pub_key,
		  const unsigned char *pri_key,
		  SM2_SIGNATURE_STRUCT *sm2_sig);

/**************************************************
* Name: sm2_verify_sig
* Function: verify SM2 signature
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    sm2_sig[out]     SM2 signature
* Return value:
    0:                signature passes verification
    any other value:  an error occurs
* Notes:
1. "pub_key" is a octet string of 65 byte length. It 
   is a concatenation of 04 || X || Y. X and Y both are 
   SM2 public key coordinates of 32-byte length.
**************************************************/
int sm2_verify_sig(const unsigned char *message,
                   const int message_len,
		   const unsigned char *id,
		   const int id_len,
		   const unsigned char *pub_key,
		   SM2_SIGNATURE_STRUCT *sm2_sig);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_SM2_SIGN_AND_VERIFY_COMPUTATION_H */
