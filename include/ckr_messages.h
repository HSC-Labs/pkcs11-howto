/**
 * Error messages for PKCS#11 error codes
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

#ifndef _CKR_MESSAGES_H_
#define _CKR_MESSAGES_H_

/**
 * Get the textual description of a PKCS#11 return code
 *
 * \param rv PKCS#11 return code
 *
 * \return a string containing the error description
 * 
 */ 
const char * p11_get_message( CK_RV rv );

#define CKRMSG_OK                                ("OK: Success")
#define CKRMSG_ARGUMENTS_BAD                     ("ARGUMENT_BAD: Inappropriate arguments")
#define CKRMSG_ATTRIBUTE_READ_ONLY               ("ATTRIBUTE_READ_ONLY: Changing a read-only attribute is not permited")
#define CKRMSG_ATTRIBUTE_SENSITIVE               ("ATTRIBUTE_SENSITIVE: Accessing a sensitive or non-extractable marked object is forbidden")
#define CKRMSG_ATTRIBUTE_TYPE_INVALID            ("ATTRIBUTE_TYPE_INVALID: You specified an invalid attribute type")
#define CKRMSG_ATTRIBUTE_VALUE_INVALID           ("ATTRIBUTE_VALUE_INVALID: An invalid value was speficied for a particular attribute in a template" )
#define CKRMSG_BUFFER_TOO_SMALL                  ("BUFFER_TOO_SMALL: The output of the function is too large to fit in the supplied buffer")
#define CKRMSG_CANCEL                            ("CANCEL: Operation was canceled")
#define CKRMSG_CANT_LOCK                         ("CANT_LOCK: The type of locking requested by the application for thread-safety is not available in this library.")
#define CKRMSG_CRYPTOKI_ALREADY_INITIALIZED      ("CRYPTOKI_ALREADY_INITIALIZED: The Cryptoki library has already been initialized")
#define CKRMSG_CRYPTOKI_NOT_INITIALIZED          ("CRYPTOKI_NOT_INITIALIZED: The function cannot be executed because the Cryptoki library has not yet been initialized.")
#define CKRMSG_DATA_INVALID                      ("DATA_INVALID: The plaintext input data to a cryptographic operation is invalid.")
#define CKRMSG_DATA_LEN_RANGE                    ("DATA_LEN_RANGE: The plaintext input data to a cryptographic operation has a bad length")
#define CKRMSG_DEVICE_ERROR                      ("DEVICE_ERROR: Device encountered an internal error.")
#define CKRMSG_DEVICE_MEMORY                     ("DEVICE_MEMORY: Device memory is saturated.")
#define CKRMSG_DEVICE_REMOVED                    ("DEVICE_REMOVED: Device was unplugged.")
#define CKRMSG_DOMAIN_PARAMS_INVALID             ("DOMAIN_PARAMS_INVALID: Invalid or unsupported domain parameters were supplied to the function.")
#define CKRMSG_ENCRYPTED_DATA_INVALID            ("ENCRYPTED_DATA_INVALID: The plaintext input data to a cryptographic operation is invalid")
#define CKRMSG_ENCRYPTED_DATA_LEN_RANGE          ("ENCRYPTED_DATA_LEN_RANGE: The plaintext input data to a cryptographic operation has a bad length")
#define CKRMSG_FUNCTION_CANCELED                 ("FUNCTION_CANCELED: The function was canceled in mid-execution.")
#define CKRMSG_FUNCTION_FAILED                   ("FUNCTION_FAILED: The function call failed for an unspecified reason")
#define CKRMSG_FUNCTION_NOT_PARALLEL             ("FUNCTION_NOT_PARALLEL: There is currently no function executing in parallel in the specified session.")
#define CKRMSG_FUNCTION_NOT_SUPPORTED            ("FUNCTION_NOT_SUPPORTED: The requested function is not supported by this Cryptoki library.")
#define CKRMSG_FUNCTION_REJECTED                 ("FUNCTION_REJECTED: The signature request is rejected by the user.")
#define CKRMSG_GENERAL_ERROR                     ("GENERAL_ERROR: General error of PKCS#11.")
#define CKRMSG_HOST_MEMORY                       ("HOST_MEMORY: Host memory full.")
#define CKRMSG_INFORMATION_SENSITIVE             ("INFORMATION_SENSITIVE: The information requested could not be obtained because the token considers it sensitive, and is not able or willing to reveal it.")
#define CKRMSG_KEY_CHANGED                       ("KEY_CHANGED: One of the keys specified is not the same key that was being used in the original saved session.")
#define CKRMSG_KEY_FUNCTION_NOT_PERMITTED        ("KEY_FUNCTION_NOT_PERMITTED: An attempt has been made to use a key for a cryptographic purpose that the key'as attributes are not set to allow it to do.")
#define CKRMSG_KEY_HANDLE_INVALID                ("KEY_HANDLE_INVALID: The specified key handle is not valid.")
#define CKRMSG_KEY_INDIGESTIBLE                  ("KEY_INDIGESTIBLE: It indicates that the value of the specified key cannot be digested for some reason.")
#define CKRMSG_KEY_NEEDED                        ("KEY_NEEDED: The session state cannot be restored because C_SetOperationState needs to be supplied with one or more keys that were being used in the original saved session.")
#define CKRMSG_KEY_NOT_NEEDED                    ("KEY_NOT_NEEDED: An extraneous key was supplied to C_SetOperationState.")
#define CKRMSG_KEY_NOT_WRAPPABLE                 ("KEY_NOT_WRAPPABLE: Although the specified private or secret key does not have its CKA_UNEXTRACTABLE attribute set to CK_TRUE, Cryptoki (or the token) is unable to wrap the key as requested.") 
#define CKRMSG_KEY_SIZE_RANGE                    ("KEY_SIZE_RANGE: Although the requested keyed cryptographic operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied key‘s size is outside the range of key sizes that it can handle. ")
#define CKRMSG_KEY_TYPE_INCONSISTENT             ("KEY_TYPE_INCONSISTENT: The specified key is not the correct type of key to use with the specified mechanism.")
#define CKRMSG_KEY_UNEXTRACTABLE                 ("KEY_UNEXTRACTABLE: The specified private or secret key can’t be wrapped because its CKA_UNEXTRACTABLE attribute is set to CK_TRUE.")
#define CKRMSG_MECHANISM_INVALID                 ("MECHANISM_INVALID: An invalid mechanism was specified to the cryptographic operation.")
#define CKRMSG_MECHANISM_PARAM_INVALID           ("MECHANISM_PARAM_INVALID: Invalid parameters were supplied to the mechanism specified to the cryptographic operation.")
#define CKRMSG_MUTEX_BAD                         ("MUTEX_BAD: Mutex is invalid.")
#define CKRMSG_MUTEX_NOT_LOCKED                  ("MUTEX_NOT_LOCKED: Non locked Mutex.")
#define CKRMSG_NEED_TO_CREATE_THREADS            ("NEED_TO_CREATE_THREADS: The library cannot function properly without being able to spawn new thread (See C_Initialize parameters)")
#define CKRMSG_NEW_PIN_MODE                      ("NEW_PIN_MODE: ")
#define CKRMSG_NEXT_OTP                          ("NEXT_OTP: ")
#define CKRMSG_NO_EVENT                          ("NO_EVENT: C_GetSlotEvent called in non-blocking mode and there are no new slot events to return.")
#define CKRMSG_OBJECT_HANDLE_INVALID             ("OBJECT_HANDLE_INVALID: The specified object handle is not valid.")
#define CKRMSG_OPERATION_ACTIVE                  ("OPERATION_ACTIVE: There is already an active operation which prevents Cryptoki from activating the specified operation.")
#define CKRMSG_OPERATION_NOT_INITIALIZED         ("OPERATION_NOT_INITIALIZED: There is no active operation of a appropriate type in the specified session")
#define CKRMSG_PIN_EXPIRED                       ("PIN_EXPIRED: The specified PIN has expired, and the requested operation cannot be carried out unless C_SetPIN is called to change the PIN value.")
#define CKRMSG_PIN_INCORRECT                     ("PIN_INCORRECT: The specified PIN is incorrect.")
#define CKRMSG_PIN_INVALID                       ("PIN_INVALID: The specified PIN has invalid characters in it.")
#define CKRMSG_PIN_LEN_RANGE                     ("PIN_LEN_RANGE: The specified PIN is too long or too short.")
#define CKRMSG_PIN_LOCKED                        ("PIN_LOCKED: The specified PIN is locked, and cannot be used.")
#define CKRMSG_RANDOM_NO_RNG                     ("RANDOM_NO_RNG: This value can be returned by C_SeedRandom and C_GenerateRandom.")
#define CKRMSG_RANDOM_SEED_NOT_SUPPORTED         ("RANDOM_SEED_NOT_SUPPORTED: The token’s random number generator does not accept seeding from an application.")
#define CKRMSG_SAVED_STATE_INVALID               ("SAVED_STATE_INVALID:  the supplied saved cryptographic operations state is invalid, and so it cannot be restored to the specified session")
#define CKRMSG_SESSION_CLOSED                    ("SESSION_CLOSED: The specified session is already closed.")
#define CKRMSG_SESSION_COUNT                     ("SESSION_COUNT: The attempt to open a session  failed, either because the  token  has  to many sessions  already open, or because the token has too many read/write session already open.")
#define CKRMSG_SESSION_EXISTS                    ("SESSION_EXISTS: A session with the token is already  open.")
#define CKRMSG_SESSION_HANDLE_INVALID            ("SESSION_HANDLE_INVALID: The specified handle is not valid.")
#define CKRMSG_SESSION_PARALLEL_NOT_SUPPORTED    ("SESSION_PARALLEL_NOT_SUPPORTED: The specified token does not support parallel sessions")
#define CKRMSG_SESSION_READ_ONLY                 ("SESSION_READ_ONLY: The specified session was unable to accomplish the desired action because it is a read-only session.")
#define CKRMSG_SESSION_READ_ONLY_EXISTS          ("SESSION_READ_ONLY_EXISTS: A read-only session already exists, and so the SO cannot be logged in.")
#define CKRMSG_SESSION_READ_WRITE_SO_EXISTS      ("SESSION_READ_WRITE_SO_EXISTS: A read/write SO session already exists, and so a read-only session cannot be opened")
#define CKRMSG_SIGNATURE_INVALID                 ("SIGNATURE_INVALID: The provided signature/MAC is invalid.")
#define CKRMSG_SIGNATURE_LEN_RANGE               ("SIGNATURE_LEN_RANGE: The provided signature/MAC can be seen to be invalid solely on the basis of its length.")
#define CKRMSG_SLOT_ID_INVALID                   ("SLOT_ID_INVALID: The specified slot ID is not valid.")
#define CKRMSG_STATE_UNSAVEABLE                  ("STATE_UNSAVEABLE: The cryptographic operations state of the specified session cannot be saved for some reason.")
#define CKRMSG_TEMPLATE_INCOMPLETE               ("TEMPLATE_INCOMPLETE: The template specified for creating an object is incomplete, and lacks some necessary attributes.")
#define CKRMSG_TEMPLATE_INCONSISTENT             ("TEMPLATE_INCONSISTENT: The template specified for creating an object has conflicting attributes.")
#define CKRMSG_TOKEN_NOT_PRESENT                 ("TOKEN_NOT_PRESENT: The token is not connected to the slot.")
#define CKRMSG_TOKEN_NOT_RECOGNIZED              ("TOKEN_NOT_RECOGNIZED: The  Cryptoki library  and/or slot does not recognize the token in the slot.")
#define CKRMSG_TOKEN_WRITE_PROTECTED             ("TOKEN_WRITE_PROTECTED: The requested action could not be performed because  the  token  is  write-protected.")
#define CKRMSG_UNWRAPPING_KEY_HANDLE_INVALID     ("UNWRAPPING_KEY_HANDLE_INVALID: the  key  handle  specified  to  be  used  to  unwrap  another key is not valid.")
#define CKRMSG_UNWRAPPING_KEY_SIZE_RANGE         ("UNWRAPPING_KEY_SIZE_RANGE: although the requested unwrapping operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied key’s size is outside the range of key sizes that it can handle.")
#define CKRMSG_UNWRAPPING_KEY_TYPE_INCONSISTENT  ("UNWRAPPING_KEY_TYPE_INCONSISTENT:the type of the key specified to unwrap another key is not consistent with the mechanism specified for unwrapping.")
#define CKRMSG_USER_ALREADY_LOGGED_IN            ("USER_ALREADY_LOGGED_IN:the  specified user cannot be logged into  the session, because it is already logged into the session.")
#define CKRMSG_USER_ANOTHER_ALREADY_LOGGED_IN    ("USER_ANOTHER_ALREADY_LOGGED_IN: the specified user cannot be logged into the session, because another user is already logged into the session.")
#define CKRMSG_USER_NOT_LOGGED_IN                ("USER_NOT_LOGGED_IN:he  desired action cannot be performed because the appropriate user (or an appropriate user) is not logged in.")
#define CKRMSG_USER_PIN_NOT_INITIALIZED          ("USER_PIN_NOT_INITIALIZED: the normal user’s PIN has not yet been initialized with C_InitPIN.")
#define CKRMSG_USER_TOO_MANY_TYPES               ("USER_TOO_MANY_TYPES: An attempt was made to have more distinct users simultaneously logged into the token than the token and/or library permits.")
#define CKRMSG_USER_TYPE_INVALID                 ("USER_TYPE_INVALID: An invalid value was specified as a CK_USER_TYPE.")
#define CKRMSG_VENDOR_DEFINED                    ("VENDOR_DEFINED: Vendor defined error")
#define CKRMSG_WRAPPED_KEY_INVALID               ("WRAPPED_KEY_INVALID: The provided wrapped key is not valid.")
#define CKRMSG_WRAPPED_KEY_LEN_RANGE             ("WRAPPED_KEY_LEN_RANGE: The provided wrapped key can be seen to be invalid solely  on  the  basis  of  its  length.")
#define CKRMSG_WRAPPING_KEY_HANDLE_INVALID       ("WRAPPING_KEY_HANDLE_INVALID: The key handle specified to be used to wrap another key is not valid.")
#define CKRMSG_WRAPPING_KEY_SIZE_RANGE           ("WRAPPING_KEY_SIZE_RANGE: Although the requested wrapping operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied wrapping key’s size is outside the range of key sizes that it can handle. ")
#define CKRMSG_WRAPPING_KEY_TYPE_INCONSISTENT    ("WRAPPING_KEY_TYPE_INCONSISTENT: The type of the key specified to wrap another key is not consistent with the mechanism specified for wrapping. ")


#endif


