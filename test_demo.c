/**************************************************
* File name: test_demo.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 20th, 2018
* Description: implement test demo program for
    SM2 signature creation and verification
**************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "test_sm2_sign_and_verify.h"

/*********************************************************/
int main(void)
{
	int error_code;

	printf("/*********************************************************/\n");
	if ( error_code = test_with_input_defined_in_standard() )
	{
	   printf("Test SM2 sign data and verify signature with input defined in standard failed!\n");
	   return error_code;
	}
	else
	{
	   printf("Test SM2 sign data and verify signature with input defined in standard succeeded!\n");
	}
	
	printf("\n/*********************************************************/\n");
	if ( error_code = test_sm2_sign_and_verify() )
	{
	   printf("Test create SM2 key pair, sign data and verify signature failed!\n");
	   return error_code;
	}
	else
	{
	   printf("Test create SM2 key pair, sign data and verify signature succeeded!\n");
	}

#if defined(_WIN32) || defined(_WIN64)
        system("pause");
#endif
	return 0;
}
