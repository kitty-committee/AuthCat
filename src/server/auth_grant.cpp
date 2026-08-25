
#include "AuthCat/auth.hpp"
#include "AuthCat/oauth.hpp"
#include <AuthCat/auth_grant.hpp>
#include <cstdint>
#include <cstring>
using namespace nathcat::auth;

struct Scope nathcat::auth::extract_scope_from_auth_grant(AuthGrant grant) {
  // Initialise the scope struct
  struct Scope scope;
  std::memset(&scope, 0, sizeof(struct Scope));

  bool *pScope = (bool *)&scope;

  for (int i = 0; i < AUTH_GRANT_SCOPE_SIZE * 8; i++) {
    *pScope = (grant.scope >> i) & 1;
    pScope++;
  }

  return scope;
}

AuthGrant nathcat::auth::create_auth_grant(int user, struct Scope scope) {
  // Generate a cryptographically secure random number
  uint32_t token;
  cryptorand_generate(rng, &token, sizeof(uint32_t));

  AuthGrant grant;
  std::memset(scope.padding, 0, AUTH_GRANT_SCOPE_PADDING);

  grant.user = user;
  grant.token = token;
  grant.scope = 0;
  grant.timeIssued = util::epoch_time();

  bool *scopePointer = (bool *)&scope;
  uint8_t *bytePointer = (uint8_t *)(&grant.scope);
  int bitCount = 0;
  bool *scopeBoundary = (bool *)(&scope + 1);

  // Iterate until the end of the scope struct
  // There will always be 64 bools allocated in the scope struct, to correspond
  // with the 64 bits of the buffer scope
  while (scopePointer < scopeBoundary) {
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

uint64_t nathcat::auth::scope_to_buffer(struct Scope scope) {
  uint64_t buffer = 0;

  bool *scopeBoundary = (bool *)(&scope + 1);
  bool *scopePointer = (bool *)&scope;
  uint8_t *bufferPointer = (uint8_t *)&buffer;
  int innerCounter = 0;

  while (scopePointer < scopeBoundary) {
    *bufferPointer |= (*scopePointer) << innerCounter;
    scopePointer++;
    innerCounter++;

    if (innerCounter == 8) {
      bufferPointer++;
      innerCounter = 0;
    }
  }

  return buffer;
}
