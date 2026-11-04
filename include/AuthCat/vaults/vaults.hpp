/**
 * @file vaults.hpp
 */

#ifndef VAULTS_HPP
#define VAULTS_HPP

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace nathcat {
namespace vaults {

inline void init_crypto() {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

inline void cleanup_crypto() {
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
}

struct vault_header {};
} // namespace vaults
} // namespace nathcat
#endif
