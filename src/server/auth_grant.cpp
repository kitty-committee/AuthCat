
#include "AuthCat/auth.hpp"
#include <AuthCat/auth_grant.hpp>
#include <cstdint>
#include <cstring>
using namespace nathcat::auth;

struct Scope nathcat::auth::extract_scope_from_auth_grant(AuthGrant grant) {
  // Initialise the scope struct
  struct Scope scope;
  std::memset(&scope, 0, sizeof(struct Scope));

  // Get pointers into the internal memory of the scope struct, and the scope
  // section of the auth grant
  bool *scopePointer = (bool *)&scope;
  uint8_t *grantPointer = grant.scope;
  int innerCounter = 0;

  // Iterate until the end of the scope sectioon in the auth grant
  while (grantPointer < (grant.scope + AUTH_GRANT_SCOPE_SIZE)) {
    // If the boundary of the current byte of scope has been reached, move to
    // the next scope byte
    if (innerCounter == 8) {
      grantPointer++;
      innerCounter = 0;
    }

    // Copy the boolean value of the current scope bit into the current location
    // in the scope struct
    *scopePointer = ((*grantPointer) & (1 << innerCounter)) >> innerCounter;
    scopePointer++;
  }

  return scope;
}

AuthGrant nathcat::auth::create_auth_grant(int user, struct Scope scope) {
  // Generate a cryptographically secure random number
  uint32_t token;
  cryptorand_generate(rng, &token, sizeof(uint32_t));

  AuthGrant grant;

  grant.user = user;
  grant.token = token;

  bool *scopePointer = (bool *)&scope;
  uint8_t *bytePointer = grant.scope;
  int bitCount = 0;

  // Iterate until the end of the scope struct
  while (scopePointer < ((bool *)((&scope) + 1))) {
    // Copy the value of the current scope bool into the current bit
    *bytePointer |= (uint8_t)((*scopePointer) << bitCount);
    scopePointer++;
    bitCount++;

    // If the bit count reaches the end of the byte boundary, move to the next
    // byte
    if (bitCount == 8) {
      bytePointer++;
      bitCount = 0;
    }
  }

  return grant;
}
