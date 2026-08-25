#include "AuthCat/auth.hpp"
#include "bcrypt.h"
#include <AuthCat/auth_grant.hpp>
#include <AuthCat/oauth.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstring>
#include <regex>
#include <sstream>
using namespace nathcat::auth;
using namespace boost::multiprecision;

void nathcat::auth::token_endpoint(const httplib::Request &req,
                                   httplib::Response &res) {
  if (!req.has_param("grant_type") || !req.has_param("code") ||
      req.get_param_value("grant_type").compare("authorization_code") != 0 ||
      !req.has_header("Authorization")) {
    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("{\"error\":\"invalid_request\"}", "application/json");
    return;
  }

  std::string auth_header = req.get_header_value("Authorization");
  std::smatch auth_match;

  // The authorization header supplied is of the wrong format, respond with an
  // bad request error
  if (!std::regex_match(auth_header, auth_match, util::token_auth_regex)) {

    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("{\"error\":\"invalid_request\"}", "application/json");
    return;
  }

  std::string client_username = auth_match[1];
  std::string client_password = auth_match[2];

  // Attempt to open a connection to the database
  std::unique_ptr<sql::Connection> db;
  try {
    db = std::unique_ptr<sql::Connection>{nathcat::auth::driver->connect(
        auth::serverConfig.dbUrl, auth::serverConfig.dbUsername,
        auth::serverConfig.dbPassword)};
    db->setSchema("oauth");
  } catch (sql::SQLException &e) {
    std::cerr << "Couldn't connect to MySQL DB." << std::endl;
    std::string c = "500 - Internal error";
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content(c, "text/plain");
    return;
  }

  // Get the client information
  struct client client = util::get_client(db, client_username);
  // Validate the client's password, if invalid, respond with an invalid_client
  // error
  if (!bcrypt::validatePassword(client_password, client.password)) {
    res.status = httplib::StatusCode::Unauthorized_401;
    res.set_content("{\"error\": \"invalid_client\"}", "application/json");
    res.set_header("WWW-Authenticate", "Basic");
    return;
  }

  // At this point the client has been verified.
  // We must now verify the auth grant token
  uint128_t code_int = 0;
  std::istringstream(req.get_param_value("code")) >> std::hex >> code_int;
  AuthGrant grant = *((AuthGrant *)&code_int);

  if (!util::validate_auth_grant(db, grant, client.id)) {
    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("{\"error\":\"invalid_grant\"}", "application/json");
    return;
  }

  // Auth grant has been validated at this point, we must now create
  // an access token and serve it to the client.
}
