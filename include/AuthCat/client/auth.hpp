/**
 *@file auth.hpp
 */

#ifndef CLIENT_AUTH_HPP
#define CLIENT_AUTH_HPP

#include "../common.hpp"
#include "../db/User.hpp"
#include "AuthCat/db/Credentials.hpp"
namespace nathcat {
namespace auth {
/**
 * @class ClientConfig
 * @brief Configuration for client programs
 *
 */
struct ClientConfig {
  std::string hostUrl;
};

/**
 * @brief Stores the current client configuration for use by functions which
 * require it. This should be set by the program using the client library.
 */
extern struct ClientConfig clientConfig;

void from_json(const nlohmann::json &j, struct ClientConfig &c);

User authenticate(Credentials_Token &token);
} // namespace auth
} // namespace nathcat
#endif
