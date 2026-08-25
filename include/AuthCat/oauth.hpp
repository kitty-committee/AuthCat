/**
 * @file oauth.hpp
 */

#ifndef _OAUTH
#define _OAUTH

#include "jdbc/cppconn/connection.h"
#include <api/api.hpp>
#include <memory>

#define OAUTH_LOGIN_PAGE_PATH "Assets/html/login.html"
#define OAUTH_LOGIN_REQUEST_INVALID_PAGE_PATH                                  \
  "Assets/html/login_request_invalid.html"

namespace nathcat {
namespace auth {

struct client {
  std::string id;
  std::string redirectionUri;
  std::string password;
};

namespace util {

extern std::regex token_auth_regex;

/**
 * @brief Read the contents of a file
 */
std::string read_file(std::string path);

/**
 * @brief Get client app information from the DB
 */
struct client get_client(std::unique_ptr<sql::Connection> &db, std::string id);

} // namespace util

/**
 * @brief User authentication endpoint handler
 */
void auth_endpoint(const httplib::Request &req, httplib::Response &res);

/**
 * @brief Handles authentication form
 */
void auth_form_endpoint(const httplib::Request &req, httplib::Response &res);

/**
 * @brief Handles requests to the token endpoint, i.e. validates and grants
 * access tokens.
 */
void token_endpoint(const httplib::Request &req, httplib::Response &res);

} // namespace auth
} // namespace nathcat

#endif
