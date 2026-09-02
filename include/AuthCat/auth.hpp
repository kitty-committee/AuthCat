/**
 * @file auth.hpp
 */
#ifndef _AUTH
#define _AUTH

#include "db/Credentials.hpp"
#include "db/User.hpp"
#include "jdbc/cppconn/connection.h"
#include "jdbc/cppconn/driver.h"

#include "common.hpp"
#include <cryptorand.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#define AUTHCAT_COOKIE_NAME "AuthCat-SSO"

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
  std::string dbUrl;
  std::string dbUsername;
  std::string dbPassword;
};

extern cryptorand *rng;
extern sql::Driver *driver;
extern ServerConfig serverConfig;

void from_json(const nlohmann::json &j, struct ServerConfig &c);

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

#endif
