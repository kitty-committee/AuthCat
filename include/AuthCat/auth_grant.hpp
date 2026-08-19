/**
 * @file auth_grant.hpp
 */
#include <cstdint>
#define AUTH_GRANT_SCOPE_SIZE 8

namespace nathcat {
namespace auth {

/**
 * @class AuthGrant
 * @brief An AuthGrant is specified in 128 bytes. The first 32 specify the user,
 * followed by a 32 bit token, the remaining bytes specify grants to specific
 * resources in the order described by the Scope struct
 */
typedef struct {
  uint32_t user;
  uint32_t token;
  uint64_t scope;
} AuthGrant;

/**
 * @class Scope
 * @brief Describes the scope of an authorization
 *
 */
struct Scope {
  /**
   * @brief Potentially dangerous! This is being used as a placeholder.
   */
  bool allResources;

  bool padding[64 - 1]; // Subtract one because one is used
};

/**
 * @brief Creates an authorization grant based on a user ID and a scope of
 * access
 *
 * @param user The user granting the authorization
 * @param scope The access scope
 * @return The generated authorization code
 */
AuthGrant create_auth_grant(int user, struct Scope scope);

/**
 * @brief Extracts a scope struct from an AuthGrant
 *
 * @param grant The AuthGrant to extract from
 */
struct Scope extract_scope_from_auth_grant(AuthGrant grant);

/**
 * @brief Convert a scope struct into a buffer to be entered into an auth grant
 * token
 *
 * @param scope The scope to be converted
 * @return A 64 bit buffer containing the scope information
 */
uint64_t scope_to_buffer(struct Scope scope);
} // namespace auth
} // namespace nathcat
