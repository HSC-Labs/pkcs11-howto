/**
 * A small demonstrator of the use of a PKCS#11 token (tested with a Feitan
 * epass2003) for hardware supported random number generation.
 *
 * Authors:
 *   Olivier Houssenbay <olivier.houssebay@hsc.fr>
 *   Christophe Renard <christophe.renard@hsc.fr>
 *
 * Tous droits réservés Hervé Schauer Consultants 2016
 *
 * License and copyright: see README.md
 * 
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>

#include "pkcs11_linux.h"
#include "ckr_messages.h"

// Reading 512 bits of randomness
#define RANDOM_SIZE  (128)

// GLOBALS

// Path to the PKCS11 module
const char *p11_driver_path  = "/usr/lib/opensc-pkcs11.so";

// Seeding with 128bits
const size_t seed_size   = 32;

// Path to the system randomness source
const char * seed_source = "/dev/urandom";

// size of the b64 encoded random value buffer
const size_t  encoded_random_size = 2*RANDOM_SIZE;

// number of the slot to consider for the token
const unsigned token_num = 0;


// function pointer to the driver provided functions
CK_FUNCTION_LIST_PTR p11f; 

// pointer to the dynamic library of the driver
void * p11_lib_ptr=NULL;


/**
 * Display a message and quit
 *
 * \param fmt  printf like format string 
 */ 
void die( const char * fmt, ... ) 
{
	va_list args;
	va_start( args, fmt);

	fprintf( stderr, "ERROR: ");
	vfprintf( stderr, fmt, args);
	fprintf( stderr,"\n");

	va_end(args);	
	
	exit(-1);
}//eo die


/**
 * Checks the return of a PKCS11 call and dies if it failed
 *
 * \param rv    PKCS11 operation return code
 * \param descr description of the attempted operation
 * 
 */ 
void check_p11_return( CK_RV rv, const char* descr ) 
{
	if( rv != CKR_OK ) {
		die( "PKCS11 problem: %s failed- %08lu: %s", descr, rv, p11_get_message(rv) );
	}
}//eo check_p11_return


/**
 * Encodes a buffer to a base64 string
 *
 * \param encoded  buffer to copy the encoded string to
 * \param input    buffer containing the content to encore
 * \param len      length of the content to encode
 *
 * \return the length of the encoded string
 */  
int base64_encode(char *encoded, const uint8_t *input, size_t len)
{
	static const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *ptr = encoded;
    unsigned i;

    for( i = 0; i<(len-2); i+=3) {
        *ptr++ = basis_64[(input[i] >> 2) & 0x3F];
        *ptr++ = basis_64[((input[i] & 0x3) << 4) | ((int)(input[i+1] & 0xF0) >> 4)];
        *ptr++ = basis_64[((input[i+1] & 0xF) << 2) | ((int)(input[i+2] & 0xC0) >> 6)];
        *ptr++ = basis_64[input[i+2] & 0x3F];
    }
    if( i<len ) {
        *ptr++ = basis_64[(input[i] >> 2) & 0x3F];
        if( i == (len-1) ) {
            *ptr++ = basis_64[((input[i] & 0x3) << 4)];
            *ptr++ = '=';
        } else {
            *ptr++ = basis_64[((input[i] & 0x3) << 4) | ((int)(input[i+1] & 0xF0) >> 4)];
            *ptr++ = basis_64[((input[i+1] & 0xF) << 2)];
        }
        *ptr++ = '=';
    }

    *ptr++ = '\0';
    return ptr - encoded;
}//eo base64_encode


typedef	CK_RV (*get_function_list_ptr_t)(CK_FUNCTION_LIST_PTR_PTR); 

/**
 * Loads driver dynamic library , extract the functions list and initialize
 * the engine
 *
 * \param driver  path to the PKCS#11 driver file
 */ 
void p11_initialize( const char* driver ) 
{

	int rc = 0;

	p11_lib_ptr = dlopen( driver, RTLD_NOW );
    if ( NULL == p11_lib_ptr ) {
    	rc = errno;
    	die("Error loading PKCS#11 module '%s': 0x%X", driver, rc);
    }

    /* Get the list of the PKCS11 functions this token supports */
	get_function_list_ptr_t pC_GetFunctionList = (get_function_list_ptr_t)dlsym( p11_lib_ptr, "C_GetFunctionList");
   	if ( NULL == pC_GetFunctionList ) {
		rc = errno;
    	die("Error getting function for function list for PKCS#11 module '%s': 0x%X", driver, rc);
	}
	
	memset(&p11f,0,sizeof(CK_FUNCTION_LIST_PTR)); 
	if( CKR_OK != pC_GetFunctionList(&p11f) ) {
		die("Failed to get PKCS11 functions list for module '%s'",driver);
	} 

	/* Call the C_Initialize function in the library */ 
	CK_C_Initialize pC_Initialize = p11f->C_Initialize; 
	if( NULL == pC_Initialize ) {
		die("Failed to find init function in PKCS#11 module '%s'", driver);
	}

	if( CKR_OK != (*pC_Initialize)(NULL_PTR) ) { 
		die("PKCS11 Module '%s' failed to initialize", driver );
	}

	return;
}//eo p11_initialize


/**
 * Identifies a working token slot
 * 
 * \return the id of the token's slot
 */ 
CK_SLOT_ID p11_get_slot() 
{
	CK_RV rv;
	CK_SLOT_ID slotId;
	CK_ULONG slotCount = 10;

	CK_SLOT_ID *slotsIds = malloc( sizeof(CK_SLOT_ID) * slotCount);
	if( NULL == slotsIds ) {
		die("failed to allocate ids store");
	}

	rv = p11f->C_GetSlotList(CK_TRUE, slotsIds, &slotCount);
	check_p11_return(rv, "get slot list");

	if ( slotCount < 1) {
		fprintf(stderr, "Error; could not find any slots\n");
		exit(1);
	} 

	printf("slot count: %d\n", (int)slotCount );
	if( token_num > slotCount ) {
		die("Trying to access token %d/%d", token_num, slotCount);
	}

	slotId = slotsIds[token_num];
	free(slotsIds);

	return slotId;
}//eo p11_get_slot


/**
 * Initializes a session on a slot
 * 
 * \param slot_id identifier of the slot on which the token is connected
 *
 * \return a handle on the opened session
 *
 */  
CK_SESSION_HANDLE p11_open_session( CK_SLOT_ID slot_id )
{
	CK_RV rv;
	CK_SESSION_HANDLE session;

	rv = p11f->C_OpenSession( slot_id, CKF_SERIAL_SESSION, NULL, NULL, &session);
	check_p11_return(rv, "open session");

	return session;
}//eo p11_open_session


/**
 * Authenticate an open session
 *
 * \param session  a handle on an open session
 * \param pin      PIN code to use to log-in
 */ 
void p11_login(CK_SESSION_HANDLE session, const char*pin)
{
	CK_RV rv;
	if (pin) {
		rv = p11f->C_Login(session, CKU_USER, (CK_BYTE*)pin, strlen((char *)pin));
		check_p11_return(rv, "login");
	}
}//eo p11_login


/**
 * Deauthenticate an opened session
 *
 * \param session    a handle of an authenticated in session
 */ 
void p11_logout(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	rv = p11f->C_Logout(session);
	if (rv != CKR_USER_NOT_LOGGED_IN) {
		check_p11_return(rv, "logout");
	}
}//eo p11_logout


/**
 * Terminates a PKCS11 session
 *
 * \param session  a handle of an open session
 */ 
void p11_close_session( CK_SESSION_HANDLE session )
{
	CK_RV rv = p11f->C_CloseSession(session);
	check_p11_return(rv, "close session");
}//eo p11_end_session


/**
 * Unload driver 
 */   
void p11_finalize()
{
	p11f->C_Finalize(NULL);

	if(NULL != p11_lib_ptr) {
		dlclose(p11_lib_ptr);
	}
}//eo p11_finalize


/**
 * Seeds the token RNG with external randomness
 *
 * \param session a handle of an authenticated in session
 * \param data    data to seed the RNG with
 * \param sze     size of the data to seed
 *
 */ 
void p11_seed_random( CK_SESSION_HANDLE session, const uint8_t* data, size_t sze ) 
{
	
	CK_RV rv = p11f->C_SeedRandom( session, (CK_BYTE_PTR)data, (CK_ULONG)sze );
	if( rv == CKR_OK) return;

	switch( rv ) {
		case CKR_RANDOM_SEED_NOT_SUPPORTED:
			fprintf(stderr, "RNG seeding not supported\n");
			return;
		case CKR_FUNCTION_NOT_SUPPORTED:
			fprintf(stderr, "Seeding function not supported\n");
			return;
		default:
			check_p11_return(rv, "random generator seeding");
	}

}//eo p11_seed_random


/**
 * Gets some random values from the token RNG
 *
 * \param session a handle of an authenticated in session
 * \param data    buffer for the result
 * \param len     length in byte of the random value to generate
 *
 */ 
void p11_generate_random( CK_SESSION_HANDLE session, uint8_t* data, size_t len ) 
{

	CK_RV rv = p11f->C_GenerateRandom( session, (CK_BYTE_PTR)data, (CK_ULONG)len );
	check_p11_return(rv, "random generator interrogation");

}//eo p11_seed_random


///////////////////////////////////////////////////////////////////////
int main () 
{

	printf (" - Initializing pkcs11-helper\n");
	p11_initialize( p11_driver_path ); 

	printf(" - Opening session\n");
	CK_SESSION_HANDLE session = p11_open_session( p11_get_slot() );
	
	// reading some OS randomness to help the token*
	printf(" - Seeding\n");
	uint8_t seed[seed_size];
	FILE* fh = fopen(seed_source,"r");
	if( fread( seed, 1, seed_size, fh ) != seed_size ) {
		die( "Failed to read %d bits from %s", seed_size*8, seed_source );
	}
	fclose(fh);

	// Some drivers/tokens do not support seeding 
	// (most notably Feitan epass2003)
	// in which case we just print a warning
	p11_seed_random( session, seed, seed_size);

	printf(" - Generating\n");
    uint8_t random_buffer[RANDOM_SIZE];
    p11_generate_random( session, random_buffer, RANDOM_SIZE);

	printf(" - Encoding\n");
    char encoded_random[encoded_random_size]; 
    base64_encode( encoded_random, random_buffer, RANDOM_SIZE);

    printf("Encoded random value (%d bits): %s\n", RANDOM_SIZE*8, encoded_random);

	p11_close_session(session);

	p11_finalize();


	exit (0);
	return 0;
}


