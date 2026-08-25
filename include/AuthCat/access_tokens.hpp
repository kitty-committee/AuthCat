/**
 * @file access_tokens.hpp
 */

#ifndef ACCESS_TOKENS_HPP
#define ACCESS_TOKENS_HPP

#include "auth_grant.hpp"
#include <cstdint>

#define ACCESS_TOKEN_EXPIRY_TIME 86400

namespace nathcat {
namespace auth {
typedef struct {
  uint32_t grant_token;
  uint64_t token;
  uint64_t timeIssued;
} AccessToken;

/**
 * @brief Create an access token from an auth grant
 *
 * @param grant The auth grant to use
 * @return The generated access token
 */
AccessToken create_access_token(AuthGrant grant);

} // namespace auth
} // namespace nathcat
#endif
