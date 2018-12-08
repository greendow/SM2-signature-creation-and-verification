/**************************************************
* File name: sm3_with_preprocess.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 17th, 2018
* Description: declare SM3 hash calculation with 
    preprocess functions
* Note: SM3 digest with preprocess instead of "pure" 
    SM3 digest is used as one input item in computation 
    of SM2 signature.
**************************************************/

#ifndef HEADER_SM3_DIGEST_WTIH_PREPROCESS_COMPUTATION_H
  #define HEADER_SM3_DIGEST_WTIH_PREPROCESS_COMPUTATION_H

#ifdef  __cplusplus
  extern "C" {
#endif

/**************************************************
* Name: sm3_digest_z
* Function: compute digest of leading Z in SM3 preprocess
* Parameters:
    id[in]       user id
    id_len[in]   user id length, size in bytes
    pub_key[in]  SM2 public key
    digest[out]  digest value on Z
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
**************************************************/
int sm3_digest_z(const unsigned char *id,
                 const int id_len,
		 const unsigned char *pub_key,
		 unsigned char *z_digest);

/**************************************************
* Name: sm3_digest_with_preprocess
* Function: compute SM3 digest with preprocess
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    digest[out]      digest value of SM3 preprocess
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
**************************************************/
int sm3_digest_with_preprocess(const unsigned char *message,
                               const int message_len,
                               const unsigned char *id,
			       const int id_len,
			       const unsigned char *pub_key,
                               unsigned char *digest);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_SM3_DIGEST_WTIH_PREPROCESS_COMPUTATION_H */
