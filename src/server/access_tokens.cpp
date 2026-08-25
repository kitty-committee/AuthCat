#include <AuthCat/access_tokens.hpp>
#include <AuthCat/auth.hpp>
#include <AuthCat/oauth.hpp>
using namespace nathcat::auth;

AccessToken nathcat::auth::create_access_token(AuthGrant grant) {
  uint64_t token;
  cryptorand_generate(rng, &token, sizeof(uint64_t));

  return {grant.token, token, util::epoch_time()};
}
