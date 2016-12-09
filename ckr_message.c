/**
 * A small function to convert CKR codes to messages
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
#include "pkcs11_linux.h"
#include "ckr_messages.h"

const char* p11_get_message( CK_RV rv )
{
    switch ( rv ) {
        case CKR_OK                               : return CKRMSG_OK;
        case CKR_ARGUMENTS_BAD                    : return CKRMSG_ARGUMENTS_BAD;
        case CKR_ATTRIBUTE_READ_ONLY              : return CKRMSG_ATTRIBUTE_READ_ONLY;
        case CKR_ATTRIBUTE_SENSITIVE              : return CKRMSG_ATTRIBUTE_SENSITIVE;
        case CKR_ATTRIBUTE_TYPE_INVALID           : return CKRMSG_ATTRIBUTE_TYPE_INVALID;
        case CKR_ATTRIBUTE_VALUE_INVALID          : return CKRMSG_ATTRIBUTE_VALUE_INVALID;
        case CKR_BUFFER_TOO_SMALL                 : return CKRMSG_BUFFER_TOO_SMALL;
        case CKR_CANCEL                           : return CKRMSG_CANCEL;
        case CKR_CANT_LOCK                        : return CKRMSG_CANT_LOCK;
        case CKR_CRYPTOKI_ALREADY_INITIALIZED     : return CKRMSG_CRYPTOKI_ALREADY_INITIALIZED;
        case CKR_CRYPTOKI_NOT_INITIALIZED         : return CKRMSG_CRYPTOKI_NOT_INITIALIZED;
        case CKR_DATA_INVALID                     : return CKRMSG_DATA_INVALID;
        case CKR_DATA_LEN_RANGE                   : return CKRMSG_DATA_LEN_RANGE;
        case CKR_DEVICE_ERROR                     : return CKRMSG_DEVICE_ERROR;
        case CKR_DEVICE_MEMORY                    : return CKRMSG_DEVICE_MEMORY;
        case CKR_DEVICE_REMOVED                   : return CKRMSG_DEVICE_REMOVED;
        case CKR_DOMAIN_PARAMS_INVALID            : return CKRMSG_DOMAIN_PARAMS_INVALID ;
        case CKR_ENCRYPTED_DATA_INVALID           : return CKRMSG_ENCRYPTED_DATA_INVALID;
        case CKR_ENCRYPTED_DATA_LEN_RANGE         : return CKRMSG_ENCRYPTED_DATA_LEN_RANGE;
        case CKR_FUNCTION_CANCELED                : return CKRMSG_FUNCTION_CANCELED;
        case CKR_FUNCTION_FAILED                  : return CKRMSG_FUNCTION_FAILED;
        case CKR_FUNCTION_NOT_PARALLEL            : return CKRMSG_FUNCTION_NOT_PARALLEL ;
        case CKR_FUNCTION_NOT_SUPPORTED           : return CKRMSG_FUNCTION_NOT_SUPPORTED;
        case CKR_FUNCTION_REJECTED                : return CKRMSG_FUNCTION_REJECTED;
        case CKR_GENERAL_ERROR                    : return CKRMSG_GENERAL_ERROR;
        case CKR_HOST_MEMORY                      : return CKRMSG_HOST_MEMORY;
        case CKR_INFORMATION_SENSITIVE            : return CKRMSG_INFORMATION_SENSITIVE;
        case CKR_KEY_CHANGED                      : return CKRMSG_KEY_CHANGED;
        case CKR_KEY_FUNCTION_NOT_PERMITTED       : return CKRMSG_KEY_FUNCTION_NOT_PERMITTED;
        case CKR_KEY_HANDLE_INVALID               : return CKRMSG_KEY_HANDLE_INVALID;
        case CKR_KEY_INDIGESTIBLE                 : return CKRMSG_KEY_INDIGESTIBLE;
        case CKR_KEY_NEEDED                       : return CKRMSG_KEY_NEEDED;
        case CKR_KEY_NOT_NEEDED                   : return CKRMSG_KEY_NOT_NEEDED;
        case CKR_KEY_NOT_WRAPPABLE                : return CKRMSG_KEY_NOT_WRAPPABLE;
        case CKR_KEY_SIZE_RANGE                   : return CKRMSG_KEY_SIZE_RANGE;
        case CKR_KEY_TYPE_INCONSISTENT            : return CKRMSG_KEY_TYPE_INCONSISTENT   ;
        case CKR_KEY_UNEXTRACTABLE                : return CKRMSG_KEY_UNEXTRACTABLE       ;
        case CKR_MECHANISM_INVALID                : return CKRMSG_MECHANISM_INVALID       ;
        case CKR_MECHANISM_PARAM_INVALID          : return CKRMSG_MECHANISM_PARAM_INVALID ;
        case CKR_MUTEX_BAD                        : return CKRMSG_MUTEX_BAD               ;
        case CKR_MUTEX_NOT_LOCKED                 : return CKRMSG_MUTEX_NOT_LOCKED        ;
        case CKR_NEED_TO_CREATE_THREADS           : return CKRMSG_NEED_TO_CREATE_THREADS  ;
        case CKR_NEW_PIN_MODE                     : return CKRMSG_NEW_PIN_MODE            ;
        case CKR_NEXT_OTP                         : return CKRMSG_NEXT_OTP                ;
        case CKR_NO_EVENT                         : return CKRMSG_NO_EVENT                ;
        case CKR_OBJECT_HANDLE_INVALID            : return CKRMSG_OBJECT_HANDLE_INVALID   ;
        case CKR_OPERATION_ACTIVE                 : return CKRMSG_OPERATION_ACTIVE        ;
        case CKR_OPERATION_NOT_INITIALIZED        : return CKRMSG_OPERATION_NOT_INITIALIZED;
        case CKR_PIN_EXPIRED                      : return CKRMSG_PIN_EXPIRED  ;
        case CKR_PIN_INCORRECT                    : return CKRMSG_PIN_INCORRECT;
        case CKR_PIN_INVALID                      : return CKRMSG_PIN_INVALID  ;
        case CKR_PIN_LEN_RANGE                    : return CKRMSG_PIN_LEN_RANGE;
        case CKR_PIN_LOCKED                       : return CKRMSG_PIN_LOCKED   ;
        case CKR_RANDOM_NO_RNG                    : return CKRMSG_RANDOM_NO_RNG;
        case CKR_RANDOM_SEED_NOT_SUPPORTED        : return CKRMSG_RANDOM_SEED_NOT_SUPPORTED;
        case CKR_SAVED_STATE_INVALID              : return CKRMSG_SAVED_STATE_INVALID      ;
        case CKR_SESSION_CLOSED                   : return CKRMSG_SESSION_CLOSED           ;
        case CKR_SESSION_COUNT                    : return CKRMSG_SESSION_COUNT            ;
        case CKR_SESSION_EXISTS                   : return CKRMSG_SESSION_EXISTS           ;
        case CKR_SESSION_HANDLE_INVALID           : return CKRMSG_SESSION_HANDLE_INVALID   ;
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED   : return CKRMSG_SESSION_PARALLEL_NOT_SUPPORTED;
        case CKR_SESSION_READ_ONLY                : return CKRMSG_SESSION_READ_ONLY             ;
        case CKR_SESSION_READ_ONLY_EXISTS         : return CKRMSG_SESSION_READ_ONLY_EXISTS;
        case CKR_SESSION_READ_WRITE_SO_EXISTS     : return CKRMSG_SESSION_READ_WRITE_SO_EXISTS  ;
        case CKR_SIGNATURE_INVALID                : return CKRMSG_SIGNATURE_INVALID  ;
        case CKR_SIGNATURE_LEN_RANGE              : return CKRMSG_SIGNATURE_LEN_RANGE;
        case CKR_SLOT_ID_INVALID                  : return CKRMSG_SLOT_ID_INVALID    ;
        case CKR_STATE_UNSAVEABLE                 : return CKRMSG_STATE_UNSAVEABLE   ;
        case CKR_TEMPLATE_INCOMPLETE              : return CKRMSG_TEMPLATE_INCOMPLETE;
        case CKR_TEMPLATE_INCONSISTENT            : return CKRMSG_TEMPLATE_INCONSISTENT;
        case CKR_TOKEN_NOT_PRESENT                : return CKRMSG_TOKEN_NOT_PRESENT    ;
        case CKR_TOKEN_NOT_RECOGNIZED             : return CKRMSG_TOKEN_NOT_RECOGNIZED ;
        case CKR_TOKEN_WRITE_PROTECTED            : return CKRMSG_TOKEN_WRITE_PROTECTED;
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID    : return CKRMSG_UNWRAPPING_KEY_HANDLE_INVALID;
        case CKR_UNWRAPPING_KEY_SIZE_RANGE        : return CKRMSG_UNWRAPPING_KEY_SIZE_RANGE;
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT : return CKRMSG_UNWRAPPING_KEY_TYPE_INCONSISTENT;
        case CKR_USER_ALREADY_LOGGED_IN           : return CKRMSG_USER_ALREADY_LOGGED_IN;
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN   : return CKRMSG_USER_ANOTHER_ALREADY_LOGGED_IN;
        case CKR_USER_NOT_LOGGED_IN               : return CKRMSG_USER_NOT_LOGGED_IN;
        case CKR_USER_PIN_NOT_INITIALIZED         : return CKRMSG_USER_PIN_NOT_INITIALIZED;
        case CKR_USER_TOO_MANY_TYPES              : return CKRMSG_USER_TOO_MANY_TYPES;
        case CKR_USER_TYPE_INVALID                : return CKRMSG_USER_TYPE_INVALID;
        case CKR_VENDOR_DEFINED                   : return CKRMSG_VENDOR_DEFINED;
        case CKR_WRAPPED_KEY_INVALID              : return CKRMSG_WRAPPED_KEY_INVALID;
        case CKR_WRAPPED_KEY_LEN_RANGE            : return CKRMSG_WRAPPED_KEY_LEN_RANGE;
        case CKR_WRAPPING_KEY_HANDLE_INVALID      : return CKRMSG_WRAPPING_KEY_HANDLE_INVALID;
        case CKR_WRAPPING_KEY_SIZE_RANGE          : return CKRMSG_WRAPPING_KEY_SIZE_RANGE;
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT   : return CKRMSG_WRAPPING_KEY_TYPE_INCONSISTENT;
        default: return "Unknown PKCS11 error code";
    };
}    


