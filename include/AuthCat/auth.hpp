/**
 * @file auth.hpp
 */

#include "db/Credentials.hpp"
#include "db/User.hpp"
#include "jdbc/cppconn/connection.h"
#include <exception>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace nathcat {
namespace auth {

/**
 * @class ServerConfig
 * @brief Configuration for the server program
 *
 */
struct ServerConfig {
  std::string host;
  int port;
};

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
nathcat::auth::User authenticate(std::unique_ptr<sql::Connection> &sql,
                                 Credentials &creds);

/**
 * @brief Attempt to authenticate a token
 *
 * @param creds The token to authenticate
 * @throws AuthFailed
 */
nathcat::auth::User authenticate(std::unique_ptr<sql::Connection> &sql,
                                 Credentials_Token &creds);

/**
 * @brief Get a user by their unique ID
 *
 * @param id The unique ID of the user
 * @throws NotFound
 */
nathcat::auth::User getById(std::unique_ptr<sql::Connection> &sql, int id);

/**
 * @brief Search for a set of users by their username
 *
 * @param username The username to search for
 */
std::vector<User> searchByUsername(std::unique_ptr<sql::Connection> &sql,
                                   std::string username);

/**
 * @brief Search for a set of users by their full name.
 *
 * @param username The name to search for
 */
std::vector<User> searchByFullName(std::unique_ptr<sql::Connection> &sql,
                                   std::string fullName);
} // namespace auth
} // namespace nathcat
