/**************************************************
* File name: test_sm2_sign_and_verify.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 20th, 2018
* Description: declare SM2 sign data and verify
    signature test functions
**************************************************/

#ifndef HEADER_SM2_SIGN_DATA_AND_VERIFY_SIGNATURE_TEST_H
  #define HEADER_SM2_SIGN_DATA_AND_VERIFY_SIGNATURE_TEST_H

#ifdef  __cplusplus
  extern "C" {
#endif

/**************************************************
* Name: test_with_input_defined_in_standard
* Function: test SM2 sign data and verify signature
    with standard input from GM/T 0003.5-2012
* Return value:
    0:                test executes successfully
    any other value:  an error occurs
**************************************************/
int test_with_input_defined_in_standard(void);

/**************************************************
* Name: test_sm2_sign_and_verify
* Function: test SM2 sign data and verify signature
* Return value:
    0:                test executes successfully
    any other value:  an error occurs
**************************************************/
int test_sm2_sign_and_verify(void);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_SM2_SIGN_DATA_AND_VERIFY_SIGNATURE_TEST_H */