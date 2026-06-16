/**
 * @file auth.hpp
 * @brief For client applications, specify AUTHCAT_CLIENT_MODE before including
 * this file
 */

#include "db/Credentials.hpp"
#include "db/User.hpp"

#ifndef AUTHCAT_CLIENT_MODE
#include "jdbc/cppconn/connection.h"
#endif

#include <exception>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#define AUTHCAT_COOKIE_NAME "AuthCat-SSO"

namespace nathcat {
namespace auth {

#ifndef AUTHCAT_CLIENT_MODE
/**
 * @class ServerConfig
 * @brief Configuration for the server program
 *
 */
struct ServerConfig {
  std::string host;
  int port;
};
#endif

#ifdef AUTHCAT_CLIENT_MODE
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
static struct ClientConfig clientConfig;
#endif

/**
 * @brief Get the program configuration
 *
 * @tparam Conf The expected config type
 * @param path The file location of the config
 */
template <typename Conf> Conf getConfig(std::string path) {
  std::ifstream f(path);
  nlohmann::json data = nlohmann::json::parse(f);

  f.close();
  return data.get<Conf>();
}

class AuthFailed : std::exception {};

class NotFound : std::exception {};

/**
 * @brief Attempt to authenticate a set of credentials
 *
 * @param creds The credentials to authenticate
 * @throws AuthFailed
 */
nathcat::auth::User authenticate(
#ifndef AUTHCAT_CLIENT_MODE
    std::unique_ptr<sql::Connection> &sql,
#endif
    Credentials &creds);

/**
 * @brief Attempt to authenticate a token
 *
 * @param creds The token to authenticate
 * @throws AuthFailed
 */
nathcat::auth::User authenticate(
#ifndef AUTHCAT_CLIENT_MODE
    std::unique_ptr<sql::Connection> &sql,
#endif
    Credentials_Token &creds);

/**
 * @brief Get a user by their unique ID
 *
 * @param id The unique ID of the user
 * @throws NotFound
 */
nathcat::auth::User getById(
#ifndef AUTHCAT_CLIENT_MODE
    std::unique_ptr<sql::Connection> &sql,
#endif
    int id);

/**
 * @brief Search for a set of users by their username
 *
 * @param username The username to search for
 */
std::vector<User> searchByUsername(
#ifndef AUTHCAT_CLIENT_MODE
    std::unique_ptr<sql::Connection> &sql,
#endif

    std::string username);

/**
 * @brief Search for a set of users by their full name.
 *
 * @param username The name to search for
 */
std::vector<User> searchByFullName(
#ifndef AUTHCAT_CLIENT_MODE
    std::unique_ptr<sql::Connection> &sql,
#endif

    std::string fullName);
} // namespace auth
} // namespace nathcat
