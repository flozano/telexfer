/*
 * ftam_pdu.h - ISO 8571-4 FTAM PDU tags, common types and helpers shared
 * by the initiator (client) and the test responder.
 */
#ifndef FTAM_PDU_H
#define FTAM_PDU_H

#include <stdio.h>

#include "ber.h"

/* object identifiers */
#define OID_FTAM_APP_CTX    "1.0.8571.1.1"      /* iso-ftam application context */
#define OID_FTAM_PCI        "1.0.8571.2.1"      /* FTAM PCI abstract syntax      */
#define OID_FTAM_UNSTR_TEXT "1.0.8571.2.3"      /* unstructured text AS          */
#define OID_FTAM_UNSTR_BIN  "1.0.8571.2.4"      /* unstructured binary AS        */
#define OID_FTAM_1          "1.0.8571.5.1"      /* FTAM-1 unstructured text      */
#define OID_FTAM_3          "1.0.8571.5.3"      /* FTAM-3 unstructured binary    */
#define OID_NBS9_DOC        "1.3.14.5.5.9"      /* NBS-9 file directory file     */
#define OID_NBS9_AS         "1.3.14.5.2.2"      /* NBS-9 directory entry AS      */

/* PDU choice tags ([n] IMPLICIT, context-specific constructed) */
enum {
    F_INITIALIZE_RQ = 0,  F_INITIALIZE_RP = 1,
    F_TERMINATE_RQ = 2,   F_TERMINATE_RP = 3,
    F_U_ABORT_RQ = 4,     F_P_ABORT_RQ = 5,
    F_SELECT_RQ = 6,      F_SELECT_RP = 7,
    F_DESELECT_RQ = 8,    F_DESELECT_RP = 9,
    F_CREATE_RQ = 10,     F_CREATE_RP = 11,
    F_DELETE_RQ = 12,     F_DELETE_RP = 13,
    F_READ_ATTRIB_RQ = 14, F_READ_ATTRIB_RP = 15,
    F_CHANGE_ATTRIB_RQ = 16, F_CHANGE_ATTRIB_RP = 17,
    F_OPEN_RQ = 18,       F_OPEN_RP = 19,
    F_CLOSE_RQ = 20,      F_CLOSE_RP = 21,
    F_BEGIN_GROUP_RQ = 22, F_BEGIN_GROUP_RP = 23,
    F_END_GROUP_RQ = 24,  F_END_GROUP_RP = 25,
    F_READ_RQ = 32,       F_WRITE_RQ = 33,
    F_DATA_END_RQ = 34,
    F_TRANSFER_END_RQ = 35, F_TRANSFER_END_RP = 36,
    F_CANCEL_RQ = 37,     F_CANCEL_RP = 38,
    /* filestore management (FTAM version 2); FSM-PDUs continue the
     * context-specific numbering of the other PDU groups */
    F_LIST_RQ = 43,       F_LIST_RP = 44,
};

/* Protocol-Version bits */
#define PV_VERSION_1        (1u << 0)
#define PV_VERSION_2        (1u << 1)

/* common application-wide tagged types */
#define FT_ABSTRACT_SYNTAX  T_APP(0)
#define FT_ACCESS_CONTEXT   T_APPC(1)
#define FT_ACCESS_PASSWORDS T_APPC(2)
#define FT_ACCESS_REQUEST   T_APP(3)
#define FT_ACCOUNT          T_APP(4)
#define FT_ACTION_RESULT    T_APP(5)
#define FT_CHANGE_ATTRS     T_APPC(8)
#define FT_CHARGING         T_APPC(9)
#define FT_CREATE_ATTRS     T_APPC(12)
#define FT_DIAGNOSTIC       T_APPC(13)
#define FT_DOC_TYPE_NAME    T_APP(14)
#define FT_FADU_IDENTITY    T_APPC(15)
#define FT_PASSWORD         T_APPC(17)
#define FT_READ_ATTRS       T_APPC(18)
#define FT_SELECT_ATTRS     T_APPC(19)
#define FT_STATE_RESULT     T_APP(21)
#define FT_USER_IDENTITY    T_APP(22)
#define FT_OBJECTS_ATTRS    T_APPC(25)          /* F-LIST-response list */
#define FT_ATTR_ASSERTIONS  T_APPC(26)          /* F-LIST filter (OR-Set) */
#define FT_SCOPE            T_APPC(28)          /* F-LIST scope */

/* Service-Class bits */
#define SC_UNCONSTRAINED    (1u << 0)
#define SC_MANAGEMENT       (1u << 1)
#define SC_TRANSFER         (1u << 2)
#define SC_TRANSFER_MGMT    (1u << 3)
#define SC_ACCESS           (1u << 4)

/* Functional-Units bits */
#define FU_READ             (1u << 2)
#define FU_WRITE            (1u << 3)
#define FU_FILE_ACCESS      (1u << 4)
#define FU_LIMITED_MGMT     (1u << 5)
#define FU_ENHANCED_MGMT    (1u << 6)
#define FU_GROUPING         (1u << 7)
#define FU_FADU_LOCKING     (1u << 8)
#define FU_RECOVERY         (1u << 9)
#define FU_RESTART          (1u << 10)
#define FU_LIMITED_FS       (1u << 11)          /* limited filestore mgmt (v2) */

/* Attribute-Groups bits */
#define AG_STORAGE          (1u << 0)
#define AG_SECURITY         (1u << 1)
#define AG_PRIVATE          (1u << 2)

/* Access-Request / Permitted-Actions bits */
#define AR_READ             (1u << 0)
#define AR_INSERT           (1u << 1)
#define AR_REPLACE          (1u << 2)
#define AR_EXTEND           (1u << 3)
#define AR_ERASE            (1u << 4)
#define AR_READ_ATTR        (1u << 5)
#define AR_CHANGE_ATTR      (1u << 6)
#define AR_DELETE           (1u << 7)
#define PA_TRAVERSAL        (1u << 8)

/* processing-mode bits (F-OPEN) */
#define PM_READ             (1u << 0)
#define PM_INSERT           (1u << 1)
#define PM_REPLACE          (1u << 2)
#define PM_EXTEND           (1u << 3)
#define PM_ERASE            (1u << 4)

/* F-WRITE file-access-data-unit-operation */
enum { FADU_OP_INSERT = 0, FADU_OP_REPLACE = 1, FADU_OP_EXTEND = 2 };

/* F-CREATE override */
enum {
    OVR_CREATE_FAILURE = 0,
    OVR_SELECT_OLD = 1,
    OVR_DELETE_CREATE_OLD_ATTRS = 2,
    OVR_DELETE_CREATE_NEW_ATTRS = 3,
};

/* access-context values */
enum { AC_FLAT_ALL = 2, AC_UNSTRUCTURED_ALL = 5 };

/* FTAM-1/FTAM-3 string significance */
enum { SS_VARIABLE = 0, SS_FIXED = 1, SS_NOT_SIGNIFICANT = 2 };

/* Attribute-Names bits (F-READ-ATTRIB, F-LIST, NBS-9 parameter) */
#define AN_PATHNAME         (1u << 0)
#define AN_PERMITTED        (1u << 1)
#define AN_CONTENTS_TYPE    (1u << 2)
#define AN_MODIFIED         (1u << 5)
#define AN_SIZE             (1u << 13)
#define AN_OBJECT_TYPE      (1u << 18)          /* version 2 */

/* Contents type (document type + parameters) */
typedef struct {
    int  doctype;               /* 1 = FTAM-1, 3 = FTAM-3, 9 = NBS-9,
                                   0 = unknown/other */
    char oid[64];
    long universal_class;       /* -1 absent */
    long max_string_length;     /* -1 absent */
    long significance;          /* -1 absent */
    long nbs9_names;            /* NBS-9: Attribute-Names to list, -1 absent */
} contents_type;

/* One directory entry, from a Read-Attributes value. */
typedef struct {
    char      name[512];
    int       is_dir;           /* object-type file-directory, or NBS-9 */
    long long size;             /* -1 unknown */
    char      mtime[32];        /* GeneralizedTime as sent, "" unknown */
    int       doctype;
} ftam_dirent;

/*
 * Locate the attribute set in a directory entry: a Read-Attributes value
 * itself, or wrapped (e.g. in a SEQUENCE or other tag), as the exact NBS-9
 * entry type varies between implementations.  Returns 1 if found.
 */
int  ftam_find_attributes(const ber_tlv *v, ber_tlv *attrs);
/* Extract name, type, size and modification time. */
int  ftam_parse_dirent(const ber_tlv *attrs, ftam_dirent *e);

/* Encode Contents-Type-Attribute (the CHOICE value, untagged). */
void ftam_enc_contents_type(ber_enc *e, const contents_type *ct);
/* Decode a Contents-Type-Attribute CHOICE value. */
int  ftam_dec_contents_type(const ber_tlv *t, contents_type *ct);

/* Encode a Diagnostic with a single entry. */
void ftam_enc_diagnostic(ber_enc *e, int type, int id, int observer,
                         int source, const char *details);
/* Format all Diagnostic entries found in PDU into buf; returns count. */
int  ftam_fmt_diagnostic(const ber_tlv *pdu, char *out, size_t max);
const char *ftam_error_str(long id);

/*
 * Check state-result/action-result of a response PDU.  Returns 0 if both
 * are success; otherwise -1 with an error message set, prefixed by 'what'.
 */
int  ftam_check_result(const ber_tlv *pdu, const char *what);

const char *ftam_pdu_name(unsigned tag);

/* Print a Read-Attributes value in human readable form. */
void ftam_print_attributes(FILE *f, const ber_tlv *attrs);

#endif
