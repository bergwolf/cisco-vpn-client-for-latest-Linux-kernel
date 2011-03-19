/* 
    note: the comments in this header file are used for automatic 
   documentation generation using doxygen (www.doxygen.org)
*/
#ifndef VPNAPI_H
#define VPNAPI_H

#ifdef __cplusplus
// *INDENT-OFF*
extern "C"
{
// *INDENT-ON*
#endif
#ifdef _WIN32
#include "windows_stdint.h"
#include <winsock.h>
#else
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#endif

#ifdef _MSC_VER
/* disable warning: 
    nonstandard extension used: zero-sized array in struct/union
*/
#pragma warning( disable : 4200 )
#endif

#ifdef _WIN32
#define DLL_EXPORT_NAME __declspec(dllexport)
#define CDECLAPI __cdecl
#else
typedef int SOCKET;

#define CDECLAPI
#define DLL_EXPORT_NAME
#endif

//! API version number
#define VPNAPI_VERSION 0x00010000
/**
* \defgroup constants Constants
*/
/*@{*/

/**
* \defgroup error_codes Error Codes
* error code definitions have been moved to VpnEnums.h
*/


/**
* \defgroup MSGTYPEs Message Types
* types of messages that client wants to send/recieve. These flags serve
*   2 purposes:
*   1. Requesting the right to perform an operation, such as initiating
*      a vpn tunnel.
*   2. Enabling certain different types of messages from the VPN service.
*/

//!  receive authentication messages.
/*!  only 1 channel can do this at a time
*    causes fp_auth and fp_auth_stop callbacks to be active.
*/
#define VPN_MSGTYPE_AUTH   (1<<1)

//!  receive state change updates.
/*! causes fp_state_change callback to be called whenever client state changes.
*   Any number of channels can retrieve state change messages at once. 
*/
#define VPN_MSGTYPE_STATE_CHANGE (1<<2)

//!  mask of all valid MSGTYPE bits
#define VPN_MSGTYPE_MASK (VPN_MSGTYPE_AUTH | VPN_MSGTYPE_STATE_CHANGE)

/**
* \defgroup authattrs Authentication Attributes
*/
/*@{*/
//! instructions from headend to be displayed to the user.
#define VPN_AUTH_MESSAGE      (1<<0)
//! Prompt: Username:
#define VPN_AUTH_USERNAME     (1<<1)
//! Prompt: Password:
#define VPN_AUTH_PASSWORD     (1<<2)
//! Prompt: Passcode:
#define VPN_AUTH_PASSCODE     (1<<3)
//! Prompt: Response:
#define VPN_AUTH_ANSWER       (1<<4)
//! Prompt: New PIN: & Confirm PIN:
#define VPN_AUTH_NEXTPIN      (1<<5)
//! Prompt: New Password: & Confirm Password:
#define VPN_AUTH_NEXTPASSWORD (1<<6)
//! Prompt: Domain:
#define VPN_AUTH_DOMAIN       (1<<7)
//! Prompt: PIN:     
#define VPN_AUTH_PIN          (1<<8)
//! Prompt: Next Cardcode:     
#define VPN_AUTH_TOKENCODE    (1<<9)

#define VPN_AUTH_MASK (VPN_AUTH_MESSAGE | VPN_AUTH_USERNAME | \
                       VPN_AUTH_PASSWORD | VPN_AUTH_PASSCODE | \
                       VPN_AUTH_ANSWER |  VPN_AUTH_NEXTPIN | \
                       VPN_AUTH_NEXT_PASSWORD | VPN_AUTH_DOMAIN \ \
                       VPN_AUTH_PIN | VPN_AUTH_TOKENCODE)
/*@}*/
/**
* \defgroup STATGROUPs Statistic Groups
*/
/*@{*/
//! causes struct vpn_counters to be included in returned stats
#define VPN_STATGROUP_COUNTERS      (1L<<0)
//! causes struct vpn_tunnel_info to be included in returned stats
#define VPN_STATGROUP_TUNNEL_INFO   (1L<<1)
//! causes split tunnel, secured, and local lan routes to be returned
#define VPN_STATGROUP_ROUTES        (1L<<2)
//! causes the connected profile name to be returned
#define VPN_STATGROUP_PROFILE       (1L<<3)
//! mask of all possible statgroups
#define VPN_STATGROUP_MASK (VPN_STATGROUP_COUNTERS | \
        VPN_STATGROUP_TUNNEL_INFO | \
        VPN_STATGROUP_ROUTES | \
        VPN_STATGROUP_PROFILE)
/*@}*/
/**
* \defgroup OPTIONs  Connect Options
*/
/*@{*/
//! disable shutdown messages from the cisco GUI
#define VPN_OPT_SILENT_DISCONNECT   (1L<<0)
#define VPN_OPT_MASK (VPN_OPT_SILENT_DISCONNECT)
/*@}*/
/*@}*/
/**
* \defgroup types Data Types and Structures 
*/
/*@{*/
//! return type for most functions
typedef int32_t vpn_error_t;

//!  Possible states for a VPN connection.
typedef enum
{
    VPN_MIN_STATE = -1,
    //! VPN is not connected.
    VPN_STATE_IDLE,
    //! Waiting for PPP connection to come up.
    VPN_STATE_WAIT_PPP,
    //! Waiting for cTCP handshake to complete.
    VPN_STATE_WAIT_CTCP,
    //! Waiting for IKE Phase 1 to complete.
    VPN_STATE_WAIT_PHASE1,
    //! Waiting for authentication to complete.
    VPN_STATE_WAIT_AUTH,
    //! Waiting for MODE-CFG to complete.
    VPN_STATE_WAIT_MODECFG,
    //! Waiting for IKE Phase 2 to complete.
    VPN_STATE_WAIT_PHASE2,
    //! VPN is Connected.
    VPN_STATE_CONNECTED, 
    VPN_MAX_STATE,
} vpn_state_t;

//! IPSec encryption algorithms
typedef enum
{
    VPN_MIN_CRYPTO_ALG = 0,
    //! DES
    VPN_CRYPTO_DES,
    //! 3DES
    VPN_CRYPTO_3DES,
    //! No Encryption
    VPN_CRYPTO_NULL,
    //! AES
    VPN_CRYPTO_AES,
    VPN_MAX_CRYPTO_ALG
} vpn_crypto_t;

//! IPSec authentication algorithms
typedef enum
{
    VPN_MIN_HASH = 0,
    //! HMAC-MD5
    VPN_HASH_MD5,
    //! HMAC-SHA
    VPN_HASH_SHA,
    VPN_MAX_HASH
} vpn_hash_t;

//! IP Compression algorithms
typedef enum
{ 
    VPN_MIN_COMPRESS_ALG = 0,
    //! No IP Compression
    VPN_COMPRESS_NONE,
    //! LZS
    VPN_COMPRESS_LZS, 
    VPN_MAX_COMPRESS_ALG,
} vpn_compress_t;

//! NAT pass-through algorithms
typedef enum
{ 
    VPN_MIN_NAT_MODE = 0,
    //! Normal IPSec
    VPN_NAT_NONE,
    //! IPSec over UDP 
    VPN_NAT_IPSEC_OVER_UDP,
    //! IPSec over cTCP
    VPN_NAT_IPSEC_OVER_CTCP,
    VPN_MAX_NAT_MODE
} vpn_nat_mode_t;

//! opaque representation of a communications channel with the VPN service
/*!
*   This datatype is used to issue commands and receive data from the
*   VPN service. It is intialized by calling vpn_channel_init() and
*   destroyed by calling vpn_channel_destroy()
*/
typedef void *vpn_channel_t;

//! opaque representation VPN connection statistics
/*!
*   This datastructure is accessed by the functions whose
*   names begin with "vpn_stats"   
*/
typedef void *vpn_stats_t;

//! opaque representation VPN authentication information
/*!
*   This datastructure is accessed by the functions whose
*   names begin with "vpn_auth"   
*/
typedef void *vpn_auth_t;

//! datastructure represinting an IP address
/*! this datatype is set up so that ipv6 support can be added without
    breaking binary compatibility. Also, the padding in struct ipv4 causes
    an IPv4 address stored into this structure to be in a format understood
    IPv6 address parsing routines.
*/
typedef union
{
    struct
    {
        uint32_t pad[3];

        //! IP address in network order
        struct in_addr addr;
    } ipv4;

#ifdef NOT_IMPLEMENTED
    struct
    {
        struct in6_addr addr;
    } ipv6;

#endif                          /*  */
} vpn_ip_addr_t;

//! datastructure representing a route (secured or unsecured)
struct vpn_route
{

    //! network portion of the address. (eg. 192.168.0.0)
    vpn_ip_addr_t network;

    //! netmask portion of the address. (eg. 255.255.255.0)
    vpn_ip_addr_t mask;

    //! bytes sent and received using this route.
    uint32_t bytes;

    //! is traffic secured?
    uint16_t haskeys;

    uint32_t reserved[2];
};

//! a set of routes.
struct vpn_routes
{

    //! number of entries in the routes array
    uint32_t num_routes;

    uint32_t reserved[2];

    //! contains num_routes vpn_route structures
    struct vpn_route routes[];
};

//! IPSec traffic statistics
struct vpn_counters
{

    //! number of seconds connected
    uint32_t time_connected;

    //! total bytes sent/received
    uint32_t total_bytes;

    //! 
    uint32_t bytes_sent;

    //! 
    uint32_t bytes_recieved;

    //! number of valid IPSec packets recieved
    uint32_t packets_transformed;

    //!  number of packets successfully encrypted
    uint32_t packets_encrypted;

    //!  number of packets successfully decrypted
    uint32_t packets_decrypted;

    //! number of packets sent without encryption
    uint32_t packets_bypassed;

    //! number of packets deleted by IPSec
    uint32_t packets_discarded;

    uint32_t reserved[2];
};

//! basic information about a VPN tunnel
struct vpn_tunnel_info
{

    //! address of client on the internal network
    vpn_ip_addr_t internal_addr;

    //! address of currently connected headend
    vpn_ip_addr_t peer_addr;

    //! non-zero if the exclude local lan feature is enabled
    uint8_t local_lan_enabled;

    //! nat pass through mode
    vpn_nat_mode_t nat_mode;

    //! UDP or TCP port number used for nat passthrough
    uint16_t nat_port;

    //! encryption algorithm used for securing IPSec traffic
    vpn_crypto_t crypto_algorithm;

    //! encryption key length, in bytes
    uint16_t crypto_key_length;

    //! hash algorithm used for securing IPSec traffic
    vpn_hash_t hash_algorithm;

    //! IP compression algorithm
    vpn_compress_t compress_algorithm;

    uint32_t reserved[2];
};

//! 
struct vpn_connect_error
{
    vpn_error_t error;
    uint32_t is_remote;
    char * delete_reason;

    uint32_t reserved[2];
};

/*@}*/
#ifndef VPN_API_DATATYPES_ONLY
/**
* \defgroup callbacks Callback Functions
*/
/*@{*/
//! callback for vpn_connect() results
/*!
*   \param error error code from the vpn_connect() attempt.
*   \param banner is a user displayable string that contains the login
*       banner that the headend's administrator requires all users to
*       acknowledge before connecting.
*/
typedef void (*vpn_connect_cb) (const struct vpn_connect_error *,
                                const char *banner);

//! callback for vpn_disconnect()  result
/*!
*  \param error error code from the vpn_disconnect() attempt
*/
typedef void (*vpn_disconnect_cb) (vpn_error_t error);

//! state transition callback
/*!
*   \param state new state of the vpn connection.
*   \param peer address of current headend. This may change during a
*       connection attempt due to load balancing or backup servers.
*   \param error when a state change happens because a connection
*       attempt failed, this value will indicate the reason for the
*       failure
*/
typedef void (*vpn_state_change_cb) (vpn_state_t state,
                                     const vpn_ip_addr_t * peer,
                                     const struct vpn_connect_error*);

//! callback for vpn_get_stats() results
/*!
*   \param error error code from the vpn_get_stats() attempt.
*   \param statgroups bitmask of VPN_STATGROUPS_ flags indicating which
*                     portions of the stats are available.
*   \param stats handle used for accessing the various stats structures.
*       This variable may be used only inside of this callback function.
*/
typedef void (*vpn_stats_cb) (vpn_error_t error, uint32_t stats_groups,
                              vpn_stats_t stats);

//! callback for authentication
/*!
*   \param auth handle for accessing authentication attributes.
*       This variable may be used until vpn_auth_respond() or 
*       vpn_auth_abort() is called, or vpn_auth_stop_cb() is
*       recieved.
*   \param auth_attrs bitmask of VPN_AUTH flags indicating which
*       authentication attributes were requested by the headend
*   \param allowed_save_attrs bitmask of VPN_AUTH flags indicating which
*       authentication can be saved in the profile. See the save_attrs
*       argument to vpn_auth_respond()
*   \param profile_name 
*/
typedef void (*vpn_auth_cb) (vpn_auth_t auth, uint32_t auth_attrs,
                             uint32_t allowed_save_attrs,
                             const char *profile_name);

//! callback to cancel authentication 
/*!
*   This callback is called to cancel any in-progress user authentication.
*   All authentication user interfaces should be closed, and any state
*   related to the authentication attempt should be destroyed.
*/
typedef void (*vpn_auth_stop_cb) (void);

//! structure for passing callback functions to the vpnapi
/*! 
*/
struct vpn_callback_table
{

    //! vpn_connect() callback
    vpn_connect_cb fp_connect;

    //! vpn_disconnect() callback
    vpn_disconnect_cb fp_disconnect;

    //! state change callback
    vpn_state_change_cb fp_state_change;

    //! vpn_get_stats() callback
    vpn_stats_cb fp_stats;

    //! authentication callback
    vpn_auth_cb fp_auth;

    //! authentication stop callback
    vpn_auth_stop_cb fp_auth_stop;
};

/*@}*/

/*!
* \defgroup global Global Initialization Functions
*/
/*@{*/
//! must be called before any other api functions are called.
/*!
*   \param version  On input this should be set to VPNAPI_VERSION.
*        On output it will be set to the version number supported in
*        the shared library. 
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI vpn_api_init(uint32_t * version);

//! call when done issuing api calls
DLL_EXPORT_NAME vpn_error_t CDECLAPI vpn_api_destroy(void);

/*@}*/

/*!
* \defgroup channel_functions Communications Channel Functions
* types of messages that client wants to send/recieve
*/
/*@{*/
//!  initialize a communications channel to the VPN service component
/*!
    \param channel will be set by this function
    \param msgtypes should be set to some of flags above. On return, it will
        be set to the VPN_MSGTYPEs that can actually be sent.
    \param callbacks should be initialized with pointers to the callback
        funcitons you want to use
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI
    vpn_channel_init(vpn_channel_t * channel,
                     uint32_t * msgtypes,
                     const struct vpn_callback_table *callbacks);

//!  destroy the communictations channel
/*!
    \param channel will be destroyed by this function.
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI vpn_channel_destroy(vpn_channel_t channel);

//! retreives a OS-level descriptor for the channel. 
/*! This descriptor should only be used to initialize an event loop, either
*   with select(), WaitForMultipleObjects() or similar functions
*   \param  channel
*   \returns a socket descriptor
*/
DLL_EXPORT_NAME SOCKET CDECLAPI vpn_channel_get_socket(vpn_channel_t channel);

//! event handling function
/*! call this function when the socket from vpn_channel_get_socket() becomes
*   readable. All calls to callback functions will be made from within
*   this function.
*   \param channel
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI vpn_channel_event(vpn_channel_t channel);
//! simplified event handling function
/*! this function implements a simple event loop, which calls
*   vpn_channel_event().
*   
*   this function.
*   \param channel
*   \param max_wait maximum time to wait for events.
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI
    vpn_process_events(vpn_channel_t channel, unsigned int max_wait);

//!  retrieve msgtypes flags that were set in call to vpn_channel_init()
/*!
*    \param channel
*    \returns a bitmask of VPN_MSGTYPES
*/
DLL_EXPORT_NAME uint32_t CDECLAPI
    vpn_channel_get_msgtypes(vpn_channel_t channel);

/*@}*/

/**
* \defgroup command_functions Command functions
* types of messages that client wants to send/recieve
*/
/*@{*/
//!  try to connect using a given profile. 
/*!
*   \param channel the channel to use for sending the command
*   \param profile the name of the profile
*   \param group_name the name of the profile. May be NULL if the
*       group name is saved in the profile
*   \param password is the group password or the certificate password,
*       depending on the setting of AuthType value in the profile.
*       may be NULL if the group password is saved in the profile.
*   \param option_flags bitmask of VPN_OPT_* flags.
*
*   Calling this function will cause fp_connect to be called when the
*   connection attempt suceeds. Additionally, fp_stats will be called 
*   for state changes during the connection attempt and fp_auth/fp_auth_stop
*   will be called to handle authentication.
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI
    vpn_connect(vpn_channel_t channel,
                const char *profile,
                const char *group_name,
                const char *password,
                uint32_t option_flags);

//! used to return users response to the banner given in vpn_connect_cb()
/*! 
* \param channel
* \param banner_accepted TRUE if the user agrees to the banner,
*                        FALSE if the user disagrees.
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI
    vpn_acknowledge_banner(vpn_channel_t channel,
                           int banner_accepted);

//!  disconnect the vpn tunnel.
/*! causes fp_disconnect to be called with the result of the disconnect
*   attempt. No VPN_MSGTYPE flag is needed to send.
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI vpn_disconnect(vpn_channel_t channel);

//!  request statistics to be sent
/*! causes fp_statistics to be called. no mstype needed to send.
*   \param channel
*   \param stats_groups flags describing which statistics to send.
*        use VPN_STATGROUP flags
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI
    vpn_get_stats(vpn_channel_t channel,
                  uint32_t stats_groups);

//!  Reset byte and packet counts in the statistics
/*!  no mstype needed to send.
*   \param channel
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI vpn_reset_stats(vpn_channel_t channel);

//!  reply to a fp_auth callback.
/*!  
*   This function is called to pass back authentication attributes
*   to the headend. msgtype VPN_MSGTYPE_AUTH is needed to send.
*   \param channel
*   \param auth
*   \param save_attrs a bitmask of VPN_AUTH flags indicating which
*          attributes should be saved in the profile. Attributes
*          that were not set in the allowed_save_attrs argument
*          to vpn_auth_cb will be ignored.
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI
    vpn_auth_respond(vpn_channel_t channel,
                     vpn_auth_t auth,
                     uint32_t save_attrs);

//!  negative reply to a fp_auth callback.
/*!  
*   This function is called to cancel an authentication attempt.
*   msgtype VPN_MSGTYPE_AUTH is needed to send.
*   \param channel
*   \param auth
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI
    vpn_auth_abort(vpn_channel_t channel,
                   vpn_auth_t auth);

/*@}*/

/**
* \defgroup stats_functions Statistics Functions
* Functions for accessing components of vpn_stats_t. These functions
* should only be used inside of your vpn_stats_cb. The memory
* returned by these functions is only valid in your vpn_stats_cb
* function. If need to use the data returned outside of this function,
* you should make a copy of the data.
*/
/*@{*/
//! returns list of local networks excluded from the VPN tunnel
DLL_EXPORT_NAME const struct vpn_routes * CDECLAPI
    vpn_stats_get_local_lan_routes(vpn_stats_t stats);

//! returns list of networks included in the VPN tunnel
DLL_EXPORT_NAME const struct vpn_routes * CDECLAPI
    vpn_stats_get_secure_routes(vpn_stats_t stats);

//! returns basic information about the VPN tunnel
DLL_EXPORT_NAME const struct vpn_tunnel_info * CDECLAPI
    vpn_stats_get_tunnel_info(vpn_stats_t stats);

//! returns traffic information about the VPN tunnel
DLL_EXPORT_NAME const struct vpn_counters * CDECLAPI
    vpn_stats_get_counters(vpn_stats_t stats);

//! returns the name of the profile used for the current VPN tunnel
DLL_EXPORT_NAME const char * CDECLAPI
    vpn_stats_get_profile_name(vpn_stats_t stats);

/*@}*/

/**
* \defgroup auth_functions Authentication Functions
* Functions for accessing components of vpn_auth_t. These functions
* should only be used inside of your vpn_stats_cb
*/
/*@{*/
/*!
\param auth authentication handle passed to vpn_auth_cb
\param auth_attr the authentication attribute to get
*/
DLL_EXPORT_NAME const char * CDECLAPI
    vpn_auth_get_attribute(vpn_auth_t auth,
                           uint32_t auth_attr);

/*!
\param auth authentication handle passed to vpn_auth_cb
\param auth_attr the authentication attribute to set
\param value new value for the attribute.
*/
DLL_EXPORT_NAME vpn_error_t CDECLAPI
    vpn_auth_set_attribute(vpn_auth_t auth,
                           uint32_t auth_attr,
                           const char *value);

#ifdef _WIN32
DLL_EXPORT_NAME HANDLE CDECLAPI vpn_get_service_start_event(void);
DLL_EXPORT_NAME HANDLE CDECLAPI vpn_get_gui_start_event(void);
#endif

#endif //VPN_API_DATATYPES_ONLY
/*@}*/
#ifdef _MSC_VER
/* re-enable warning: 
    nonstandard extension used: zero-sized array in struct/union
*/
#pragma warning( default: 4200 )
#endif

#ifdef __cplusplus
// *INDENT-OFF*
}
// *INDENT-ON*
#endif
#endif // VPNAPI_H
