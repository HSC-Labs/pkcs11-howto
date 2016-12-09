/*
 * Environment parameters for Linux
 * See pkcs11.h for explanation
 */
#ifndef pkcs11_linux_h
#define pkcs11_linux_h 1234

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) returnType name

#define CK_DECLARE_FUNCTION(returnType, name) returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name) 

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"
#include <stdio.h>
#include <stdlib.h>

#endif



