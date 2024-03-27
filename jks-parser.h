//TODO add license comment

///////////////
// INTERFACE //
///////////////
#ifndef JKS_PARSER_H
#define JKS_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

#include <arpa/inet.h>

#include <openssl/ssl.h>

// General Definitions Section

#define JKS_MAGIC_NUMBER 0xfeedfeed
#define JKS_VERSION_1    0x01
#define JKS_VERSION_2    0x02

// Result Section

enum jks_result {
    JKS_RESULT_OK  = 0,
    JKS_RESULT_ERR,
};

// JKS AST Section

struct jks_string {
    uint16_t data_cstr_len;
    char* data_cstr;
};

enum jks_entry_tag {
    JKS_ENTRY_TAG_PKEY = 1,
    JKS_ENTRY_TAG_CERT = 2,
};

//NOTE variants fields 'alias' and 'timestamp' could be factored out to the entry itself
//     but we prefered to let it like this to match the same encapsulation of reference implementations
struct jks_entry {
    int32_t tag;
    union jks_entry_variant {

        // In java it looks like this:
        // // Private keys and their supporting certificate chains
        // private static class KeyEntry {
        //     Date date; // the creation date of this entry
        //     byte[] protectedPrivKey;
        //     Certificate[] chain;
        // }
        struct jks_entry_variant_pkey {
            struct jks_string alias;
            int64_t timestamp;
            int32_t pkey_pkcs8_data_length;
            uint8_t* pkey_pkcs8_data;
            int32_t cert_chain_length;
        } pkey;

        // In java it looks like this:
        // private static class TrustedCertEntry {
        //     Date date; // the creation date of this entry
        //     Certificate cert;
        // }
        struct jks_entry_variant_cert {
            struct jks_string alias;
            /**
             * The creation timestamp of this entry.
             * TODO improve documentation of what kind of timestamp it is (unix epoch in seconds or ms?)
             */
            int64_t timestamp;
            //TODO in the encoding, this is a string. but maybe it's not really necessary for this to actually be a string (can we use an enum instead?)
            struct jks_string type;
            int32_t encoded_data_size;
            uint8_t* encoded_data;
            X509* data;
        } cert;
    } as;
};

//TODO add macro for append (maybe after adhoc inlining it and them factoring it out?)

// In Java, this is how entries are stored. (Hashtable, instead of dynamic array)
//TODO consider implications (like cache-locality trade-off)
// /**
//  * Private keys and certificates are stored in a hashtable.
//  * Hash entries are keyed by alias names.
//  */
// private final Hashtable<String, Object> entries;
struct jks_entries {
    struct jks_entry* items;
    size_t capacity;
    size_t count;
};

/**
 * The JKS AST data type.
 * 
 * From the OpenJDK docs:
 * 
 * > KEYSTORE FORMAT:
 * > 
 * > Magic number (big-endian integer),
 * > Version of this file format (big-endian integer),
 * > 
 * > Count (big-endian integer),
 * > followed by "count" instances of either:
 * > 
 * > {
 * >      tag=1 (big-endian integer),
 * >      alias (UTF string)
 * >      timestamp
 * >      encrypted private-key info according to PKCS #8
 * >          (integer length followed by encoding)
 * >      cert chain (integer count, then certs; for each cert,
 * >          integer length followed by encoding)
 * > }
 * > 
 * > or:
 * > 
 * > {
 * >      tag=2 (big-endian integer)
 * >      alias (UTF string)
 * >      timestamp
 * >      cert (integer length followed by encoding)
 * > }
 * > 
 * > ended by a keyed SHA1 hash (bytes only) of
 * >
 * > { password + extra data + preceding body }
 * 
 * Notes:
 * - We omitted the magic number here. no need to retain this information in the AST.
 */
struct jks {
    int32_t version;
    int32_t entries_count;  //TODO after implementation entries parsing, consider removing this redudant field
    struct jks_entries entries;
};

void jks_free(struct jks* jks);

struct jks_parser {
    FILE* input;
    size_t byte_offset;
};

void jks_parser_init(struct jks_parser* parser);
void jks_parser_free(struct jks_parser* parser);

enum jks_result jks_parser_parse_file_from_path(struct jks_parser* parser, const char* input_file_path, struct jks* out_jks);
enum jks_result jks_parser_parse(struct jks_parser* parser, struct jks* out_jks);

void jks_debug_fprintln(FILE* stream, const struct jks* jks);

#endif  // JKS_PARSER_H

////////////////////
// IMPLEMENTATION //
////////////////////
#ifdef JKS_PARSER_IMPLEMENTATION
#undef JKS_PARSER_IMPLEMENTATION

static FILE* jks_fopen(const char* file_path, const char* mode);
static bool jks_platform_is_little_endian(void);
static int64_t jks_betolell(int64_t num_be);
static enum jks_result jks_read_i32(FILE* file, int32_t* out_value);
static enum jks_result jks_read_u16(FILE* file, uint16_t* out_value);
static enum jks_result jks_read_i64(FILE* file, int64_t* out_value);
static char* jks_read_new_utf8_string(FILE* file, size_t str_len);
static enum jks_result jks_read_string(FILE* file, struct jks_string* out_str);
static enum jks_result jks_parser_parse_magic_number(struct jks_parser* parser);
static enum jks_result jks_parser_parse_version(struct jks_parser* parser, struct jks* out_jks);
static enum jks_result jks_parser_parse_entries_count(struct jks_parser* parser, struct jks* out_jks);
static enum jks_result jks_parser_parse_entries(struct jks_parser* parser, struct jks* out_jks);
static enum jks_result jks_parser_parse_entry(struct jks_parser* parser, int32_t entry_index, struct jks* out_jks);
static enum jks_result jks_parser_parse_entry_pkey(struct jks_parser* parser, int32_t entry_index, struct jks* out_jks);
static enum jks_result jks_parser_parse_entry_cert(struct jks_parser* parser, int32_t entry_index, struct jks* out_jks);
static enum jks_result jks_parser_parse_entry_cert_alias(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert);
static enum jks_result jks_parser_parse_entry_cert_timestamp(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert);
static enum jks_result jks_parser_parse_entry_cert_type(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert);
static enum jks_result jks_parser_parse_entry_cert_encoded_data_size(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert);
static enum jks_result jks_parser_parse_entry_cert_encoded_data(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert);
static void jks_string_free(struct jks_string* str);

void jks_free(struct jks* jks)
{
    assert(jks != NULL);
    for (size_t i = 0; i < jks->entries.count; i++) {
        struct jks_entry* entry = &jks->entries.items[i];
        switch (entry->tag) {
            case JKS_ENTRY_TAG_PKEY: {
                struct jks_entry_variant_pkey* pkey = &entry->as.pkey;
                //TODO implement pkey free
            } break;

            case JKS_ENTRY_TAG_CERT: {
                struct jks_entry_variant_cert* cert = &entry->as.cert;
                jks_string_free(&cert->alias);
                jks_string_free(&cert->type);
                X509_free(cert->data);
                //TODO review and also free the other fields
            } break;

            default:
                // unreachable
                assert(false);
                break;
        }
    }
}

void jks_parser_init(struct jks_parser* parser)
{
    assert(parser != NULL);

    *parser = (struct jks_parser) {
        .input = NULL,
        .byte_offset = 0,
    };
}

void jks_parser_free(struct jks_parser* parser)
{
    assert(parser != NULL);
    if (parser->input != NULL) {
        fclose(parser->input);
        parser->input = NULL;
    }
    parser->byte_offset = 0;
}

enum jks_result jks_parser_parse_file_from_path(struct jks_parser* parser, const char* input_file_path, struct jks* out_jks)
{
    assert(parser != NULL);
    assert(input_file_path != NULL);
    assert(out_jks != NULL);

    parser->input = jks_fopen(input_file_path, "rb");
    if (parser->input == NULL) {
        return JKS_RESULT_ERR;
    }

    if (jks_parser_parse(parser, out_jks) != JKS_RESULT_OK) {
        fprintf(stderr, "error: jks: parsing failed.\n");
        fclose(parser->input);
        parser->input = NULL;
        return JKS_RESULT_ERR;
    }

    return JKS_RESULT_OK;
}

enum jks_result jks_parser_parse(struct jks_parser* parser, struct jks* out_jks)
{
    if (jks_parser_parse_magic_number(parser)           != JKS_RESULT_OK) return JKS_RESULT_ERR;
    if (jks_parser_parse_version(parser, out_jks)       != JKS_RESULT_OK) return JKS_RESULT_ERR;
    if (jks_parser_parse_entries_count(parser, out_jks) != JKS_RESULT_OK) return JKS_RESULT_ERR;
    if (jks_parser_parse_entries(parser, out_jks)       != JKS_RESULT_OK) return JKS_RESULT_ERR;
    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_magic_number(struct jks_parser* parser)
{
    int32_t parsed_magic_number;
    if (jks_read_i32(parser->input, &parsed_magic_number) != 0) {
        fprintf(stderr, "error: jks: parsing: failed to read magic number.\n");
        return JKS_RESULT_ERR;
    }

    if (parsed_magic_number != (int32_t) JKS_MAGIC_NUMBER) {
        fprintf(stderr,
            "error: jks: parsing: bad magic number. "
            "expected=\"0x%08x\" actual=\"0x%08x\" byte_offset=%zu\n",
            JKS_MAGIC_NUMBER, parsed_magic_number, parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }

    parser->byte_offset += sizeof(parsed_magic_number);

    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_version(struct jks_parser* parser, struct jks* out_jks)
{
    int32_t parsed_version;
    if (jks_read_i32(parser->input, &parsed_version) != 0) {
        fprintf(stderr, 
            "error: jks: parsing: failed to read version number. "
            "byte_offset=%zu\n",
            parser->byte_offset);
        return JKS_RESULT_ERR;
    }

    const bool is_version_supported = parsed_version == JKS_VERSION_1 || parsed_version == JKS_VERSION_2;
    
    if (!is_version_supported) {
        fprintf(stderr, 
            "error: jks: parsing: unsupported version. "
            "supported_versions=[%d, %d] actual=%" PRId32 " byte_offset=%zu\n",
            JKS_VERSION_1, JKS_VERSION_2, parsed_version, parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }

    // how openjdk deals with versions...
    // if (xVersion == VERSION_1) {
    //     cf = CertificateFactory.getInstance("X509");
    // } else {
    //     // version 2
    //     cfs = new Hashtable<String, CertificateFactory>(3);
    // }

    parser->byte_offset += sizeof(parsed_version);
    out_jks->version = parsed_version;

    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_entries_count(struct jks_parser* parser, struct jks* out_jks)
{
    int32_t parsed_entries_count = 0;
    if (jks_read_i32(parser->input, &parsed_entries_count) != 0) {
        fprintf(stderr, "error: jks: parsing: failed to read entries count. byte_offset=%zu \n", parser->byte_offset);
        return JKS_RESULT_ERR;
    }

    parser->byte_offset += sizeof(parsed_entries_count);
    out_jks->entries_count = parsed_entries_count;

    // preallocate `entries_count` entries
    assert(out_jks->entries.items == NULL);
    out_jks->entries.items = calloc(out_jks->entries_count, sizeof(*out_jks->entries.items));
    if (out_jks->entries.items == NULL) {
        fprintf(stderr, "error: out of memory\n");
        return JKS_RESULT_ERR;
    }
    out_jks->entries.capacity = out_jks->entries_count;

    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_entries(struct jks_parser* parser, struct jks* out_jks)
{
    for (int32_t i = 0; i < out_jks->entries_count; i++) {
        const int32_t entry_index = i + 1;
        if (jks_parser_parse_entry(parser, entry_index, out_jks) != JKS_RESULT_OK) {
            return JKS_RESULT_ERR;
        }
    }
    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_entry(struct jks_parser* parser, int32_t entry_index, struct jks* out_jks)
{
    int32_t parsed_entry_tag = 0;
    if (jks_read_i32(parser->input, &parsed_entry_tag) != JKS_RESULT_OK) {
        fprintf(stderr, 
            "error: jks: parsing: failed to read entry tag. "
            "entry=%" PRId32 " byte_offset=%zu\n",
            entry_index,
            parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }

    switch (parsed_entry_tag) {

        //parsed_entry_tag == 1: private key entry
        case JKS_ENTRY_TAG_PKEY: {
            parser->byte_offset += sizeof(parsed_entry_tag);
            return jks_parser_parse_entry_pkey(parser, entry_index, out_jks);
        } break;

        //parsed_entry_tag == 2: trusted certificate entry
        case JKS_ENTRY_TAG_CERT: {
            parser->byte_offset += sizeof(parsed_entry_tag);
            return jks_parser_parse_entry_cert(parser, entry_index, out_jks);
        } break;

        default: {
            fprintf(stderr, 
                "error: jks: parsing: unsupported entry tag. "
                "entry=%" PRId32 " supported_tags=[%d, %d] parsed_tag=%" PRId32 " byte_offset=%zu\n",
                entry_index,
                JKS_ENTRY_TAG_PKEY,
                JKS_ENTRY_TAG_CERT,
                parsed_entry_tag,
                parser->byte_offset
            );
        }
    }
    return JKS_RESULT_ERR;
}

static enum jks_result jks_parser_parse_entry_pkey(struct jks_parser* parser, int32_t entry_index, struct jks* out_jks)
{
    (void) parser, (void) entry_index, (void) out_jks;
    fprintf(stderr, "error: TODO: implement private key entry parsing\n");
    return JKS_RESULT_ERR;
}

static enum jks_result jks_parser_parse_entry_cert(struct jks_parser* parser, int32_t entry_index, struct jks* out_jks)
{
    (void) out_jks;

    struct jks_entry entry = {
        .tag = JKS_ENTRY_TAG_CERT,
        .as.cert = {0},
    };

    if (jks_parser_parse_entry_cert_alias(parser, entry_index, &entry.as.cert) != JKS_RESULT_OK) {
        return JKS_RESULT_ERR;
    }

    if (jks_parser_parse_entry_cert_timestamp(parser, entry_index, &entry.as.cert) != JKS_RESULT_OK) {
        //TODO should I free the cert here? the parsing above allocated a string. or should the callee do that?
        return JKS_RESULT_ERR;
    }

    if (jks_parser_parse_entry_cert_type(parser, entry_index, &entry.as.cert) != JKS_RESULT_OK) {
        //TODO should I free the cert here? the parsing above allocated a string. or should the callee do that?
        return JKS_RESULT_ERR;
    }

    if (jks_parser_parse_entry_cert_encoded_data_size(parser, entry_index, &entry.as.cert) != JKS_RESULT_OK) {
        //TODO should I free the cert here? the parsing above allocated a string. or should the callee do that?
        return JKS_RESULT_ERR;
    }

    if (jks_parser_parse_entry_cert_encoded_data(parser, entry_index, &entry.as.cert) != JKS_RESULT_OK) {
        //TODO should I free the cert here? the parsing above allocated a string. or should the callee do that?
        return JKS_RESULT_ERR;
    }

    // decode X509 data
    const unsigned char* data_ptr = (const unsigned char*) entry.as.cert.encoded_data;
    entry.as.cert.data = d2i_X509(NULL, &data_ptr, entry.as.cert.encoded_data_size);
    if (entry.as.cert.data == NULL) {
        fprintf(stderr,
            "error: jks: parsing: failed to decode X509 trusted certificate "
            "entry=%" PRId32 "\n",
            entry_index
        );
        //TODO print openssl error context
        //TODO should I free the cert here? the parsing above allocated a string. or should the callee do that?
        return JKS_RESULT_ERR;
    }
    parser->byte_offset += entry.as.cert.encoded_data_size;

    //NOTE we've preallocated enough space, so reallocations should never happen. We should care about not overflowing this though.
    assert(out_jks->entries.count < out_jks->entries.capacity);
    out_jks->entries.items[out_jks->entries.count++] = entry;

    //TODO append the new entry to out_jks->entries

    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_entry_cert_alias(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert)
{
    assert(out_cert != NULL);

    if (jks_read_string(parser->input, &out_cert->alias) != JKS_RESULT_OK) {
        fprintf(stderr, 
            "error: jks: parsing: failed to read trusted certificate alias. "
            "entry=%" PRId32 " byte_offset=%zu\n",
            entry_index,
            parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }

    //TODO should be encapsulated inside jks_read_string? maybe...
    parser->byte_offset += sizeof(out_cert->alias.data_cstr_len);
    parser->byte_offset += out_cert->alias.data_cstr_len * sizeof(char);

    // fprintf(stderr, "debug: entry=%" PRId32 " alias: %s\n", entry_index, out_cert->alias.data_cstr);
    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_entry_cert_timestamp(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert)
{
    if (jks_read_i64(parser->input, &out_cert->timestamp) != 0) {
        fprintf(stderr, 
            "error: jks: parsing: failed to read trusted certificate timestamp. "
            "entry=%" PRId32 " byte_offset=%zu\n",
            entry_index,
            parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }

    if (out_cert->timestamp <= 0) {
        fprintf(stderr, 
            "error: jks: parsing: bad trusted certificate timestamp. "
            "entry=%" PRId32 " parsed_timestamp=%" PRId64 " byte_offset=%zu\n",
            entry_index,
            out_cert->timestamp,
            parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }

    parser->byte_offset += sizeof(out_cert->timestamp);

    // fprintf(stderr, "debug: entry=%" PRId32 " timestamp: %" PRId64 "\n", entry_index, out_cert->timestamp);
    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_entry_cert_type(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert)
{
    assert(out_cert != NULL);

    if (jks_read_string(parser->input, &out_cert->type) != JKS_RESULT_OK) {
        fprintf(stderr, 
            "error: jks: parsing: failed to read trusted certificate type. "
            "entry=%" PRId32 " byte_offset=%zu\n",
            entry_index,
            parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }

    if (strncmp(out_cert->type.data_cstr, "X.509", out_cert->type.data_cstr_len) != 0) {
        fprintf(stderr, 
            "error: jks: parsing: unsupported trusted certificate type. "
            "entry=%" PRId32 " parsed_cert_type=\"%s\" byte_offset=%zu\n",
            entry_index,
            out_cert->type.data_cstr,
            parser->byte_offset
        );
        //TODO should I free the cert_type here? the parsing above allocated a string. or should the callee do that?
        return JKS_RESULT_ERR;
    }

    //TODO should be encapsulated inside jks_read_string? maybe...
    parser->byte_offset += sizeof(out_cert->type.data_cstr_len);
    parser->byte_offset += out_cert->type.data_cstr_len * sizeof(char);

    // fprintf(stderr, "debug: entry=%" PRId32 " type: %s\n", entry_index, out_cert->type.data_cstr);
    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_entry_cert_encoded_data_size(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert)
{
    int32_t parsed_encoded_data_size = 0;
    if (jks_read_i32(parser->input, &parsed_encoded_data_size) != JKS_RESULT_OK) {
        fprintf(stderr, 
            "error: jks: parsing: failed to read trusted certificate encoded data size. "
            "entry=%" PRId32 " byte_offset=%zu\n",
            entry_index,
            parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }
    if (parsed_encoded_data_size < 0) {
        fprintf(stderr, 
            "error: jks: parsing: bad trusted certificate encoded data size: value should not be negative. "
            "entry=%" PRId32 " parsed_encoded_data_size=%" PRId32 " byte_offset=%zu\n",
            entry_index,
            parsed_encoded_data_size,
            parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }
    //TODO also validate for absurdly big values... what would be a reasonable limit? any clue from other implementations?

    parser->byte_offset += sizeof(parsed_encoded_data_size);
    out_cert->encoded_data_size = parsed_encoded_data_size;

    // fprintf(stderr, "debug: entry=%" PRId32 " encoded data size: %" PRId32 "\n", entry_index, out_cert->encoded_data_size);
    return JKS_RESULT_OK;
}

static enum jks_result jks_parser_parse_entry_cert_encoded_data(struct jks_parser* parser, int32_t entry_index, struct jks_entry_variant_cert* out_cert)
{
    // preallocate the buffer for the encoded certificate data
    out_cert->encoded_data = calloc(out_cert->encoded_data_size, sizeof(*out_cert->encoded_data));
    if (out_cert->encoded_data == NULL) {
        fprintf(stderr, 
            "error: jks: parsing: failed to allocate memory for reading the trusted certificate encoded data. "
            "entry=%" PRId32 " byte_offset=%zu\n",
            entry_index,
            parser->byte_offset
        );
        return JKS_RESULT_ERR;
    }

    size_t bytes_read = fread(out_cert->encoded_data, sizeof(*out_cert->encoded_data), out_cert->encoded_data_size, parser->input);
    if (ferror(parser->input) || bytes_read != (size_t) out_cert->encoded_data_size) {
        fprintf(stderr, 
            "error: jks: parsing: failed to read trusted certificate encoded data. "
            "entry=%" PRId32 " expected_data_size=%" PRId32 " bytes_read=%zu byte_offset=%zu\n",
            entry_index,
            out_cert->encoded_data_size,
            bytes_read,
            parser->byte_offset
        );
        //TODO should I free the encoded_data here? the parsing above allocated a string. or should the callee do that?
        return JKS_RESULT_ERR;
    }

    parser->byte_offset += out_cert->encoded_data_size * sizeof(*out_cert->encoded_data);

    return JKS_RESULT_OK;
}

void jks_debug_fprintln(FILE* stream, const struct jks* jks)
{
    assert(stream != NULL);
    assert(stream != stdin);
    assert(jks != NULL);

    BIO* stderr_bio = BIO_new_fp(stream, BIO_NOCLOSE);
    assert(stderr_bio != NULL);

    fprintf(stream, "\"JKS\": {\n");
    fprintf(stream, "  \"version\": %" PRId32 ",\n", jks->version);
    fprintf(stream, "  \"entriesCount\": %" PRId32 ",\n", jks->entries_count);
    fprintf(stream, "  \"entries\": [\n");
    for (size_t i = 0; i < jks->entries.count; i++) {
        const struct jks_entry* entry = &jks->entries.items[i];
        fprintf(stream, "    {\n");
        fprintf(stream, "      \"tag\": %" PRId32 "\n", entry->tag); //TODO also print a string representation of the tag
        switch (entry->tag) {
            case JKS_ENTRY_TAG_PKEY: {
                //TODO
            } break;
            
            case JKS_ENTRY_TAG_CERT: {
                const struct jks_entry_variant_cert* cert = &entry->as.cert;
                fprintf(stream, "      \"alias\": \"%s\",\n", cert->alias.data_cstr);
                fprintf(stream, "      \"timestamp\": %" PRId64 ",\n", cert->timestamp);
                fprintf(stream, "      \"type\": \"%s\",\n", cert->type.data_cstr);
                fprintf(stream, "      \"encodedDataSize\": %" PRId32 ",\n", cert->encoded_data_size);
                // uint8_t* encoded_data;
                fprintf(stream, "      \"X509\": {\n");
                
                X509_NAME* subject = X509_get_subject_name(cert->data);
                assert(subject != NULL);
                fprintf(stream, "        \"subject\": \"");
                X509_NAME_print_ex_fp(stream, subject, 0, 0);
                fprintf(stream, "\"\n");

                ASN1_TIME* cert_not_after = X509_get_notAfter(cert->data);
                assert(cert_not_after != NULL);
                
                fprintf(stream, "        \"notAfter\": \"");
                ASN1_TIME_print(stderr_bio, cert_not_after);
                fprintf(stream, "\"\n");
                
                fprintf(stream, "      }\n");
            } break;
        }
        fprintf(stream, "    },\n");
    }
    fprintf(stream, "  ]\n");
    fprintf(stream, "}\n");

    BIO_free(stderr_bio);
}

static FILE* jks_fopen(const char* file_path, const char* mode)
{
    assert(file_path != NULL);
    assert(mode != NULL);

    FILE* file = fopen(file_path, mode);
    if (file == NULL) {
        int error_code = errno;
        const char* error_msg = strerror(error_code);
        fprintf(stderr,
            "error: jks: failed to open file: [%d] %s. path=\"%s\"\n",
            error_code, error_msg,
            file_path
        );
        return NULL;
    }
    return file;
}

static bool jks_platform_is_little_endian(void)
{
    const int32_t x = 1;
    return *((char*) &x) == 1;
}

static int64_t jks_betolell(int64_t num_be)
{
    if (!jks_platform_is_little_endian()) {
        return num_be;
    }

    int64_t result = 0;

    // Loop through each byte
    for (size_t i = 0; i < sizeof(int64_t); i++) {

        // Extract the i-th byte from num_be
        const uint8_t byte = (num_be >> (8 * (sizeof(int64_t) - 1 - i))) & 0xFF;
        
        // Place the byte in the corresponding position in the result
        result |= (int64_t) byte << (8 * i);
    }

    return result;
}

static enum jks_result jks_read_i32(FILE* file, int32_t* out_value)
{
    assert(file != NULL);
    assert(out_value != NULL);

    size_t bytes_read = fread(out_value, 1, sizeof(*out_value), file);
    if (ferror(file) || bytes_read != sizeof(*out_value)) {
        *out_value = 0;
        return JKS_RESULT_ERR;
    }

    *out_value = ntohl(*out_value);

    return JKS_RESULT_OK;
}

static enum jks_result jks_read_u16(FILE* file, uint16_t* out_value)
{
    assert(file != NULL);
    assert(out_value != NULL);

    size_t bytes_read = fread(out_value, 1, sizeof(*out_value), file);
    if (ferror(file) || bytes_read != sizeof(*out_value)) {
        *out_value = 0;
        return JKS_RESULT_ERR;
    }

    *out_value = ntohs(*out_value);

    return JKS_RESULT_OK;
}

static enum jks_result jks_read_i64(FILE* file, int64_t* out_value)
{
    assert(file != NULL);
    assert(out_value != NULL);

    size_t bytes_read = fread(out_value, 1, sizeof(*out_value), file);
    if (ferror(file) || bytes_read != sizeof(*out_value)) {
        *out_value = 0;
        return JKS_RESULT_ERR;
    }

    *out_value = jks_betolell(*out_value);

    return JKS_RESULT_OK;
}

static char* jks_read_new_utf8_string(FILE* file, size_t str_len)
{
    // give it a space for the trailing '\0'
    size_t str_cap = str_len + 1;

    char* str = calloc(str_cap, sizeof(char));
    if (str == NULL) {
        fprintf(stderr, "error: jks: failed to allocate %zu bytes\n", str_cap);
        return NULL;
    }

    size_t bytes_read = fread(str, sizeof(*str), str_len, file);
    if (ferror(file) || bytes_read != str_len) {
        fprintf(stderr, "error: jks: failed to read utf-8 string\n");
        goto err;
    }

    //TODO check if the buffer is really a utf-8 string
    return str;

err:
    free(str);
    return NULL;
}

static enum jks_result jks_read_string(FILE* file, struct jks_string* out_str)
{
    assert(file != NULL);
    assert(out_str != NULL);

    if (jks_read_u16(file, &out_str->data_cstr_len) != 0) {
        fprintf(stderr, "error: jks: failed to read string u16 length\n");
        return JKS_RESULT_ERR;
    }
    if (out_str->data_cstr_len == 0) {
        fprintf(stderr, "error: jks: reading string with length 0 is not supported\n");
        return JKS_RESULT_ERR;
    }
    if (out_str->data_cstr_len > 4096) {
        fprintf(stderr, "error: jks: reading string with length higher than 4096 is not supported\n");
        return JKS_RESULT_ERR;
    }

    out_str->data_cstr = jks_read_new_utf8_string(file, out_str->data_cstr_len);
    if (out_str->data_cstr == NULL) {
        fprintf(stderr, "error: jks: failed to read string\n");
        return JKS_RESULT_ERR;
    };

    return JKS_RESULT_OK;
}

static void jks_string_free(struct jks_string* str)
{
    assert(str != NULL);
    assert(str->data_cstr != NULL);

    free(str->data_cstr);
    str->data_cstr = NULL;
    str->data_cstr_len = 0;
}

#endif
