#include "AuthCat/auth.hpp"
#include "bcrypt.h"
#include "jdbc/cppconn/exception.h"
#include "jdbc/cppconn/prepared_statement.h"
#include <AuthCat/access_tokens.hpp>
#include <AuthCat/auth_grant.hpp>
#include <AuthCat/oauth.hpp>
#include <boost/multiprecision/cpp_int.hpp>
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
  AccessToken access_token = create_access_token(grant);

  try {
    std::unique_ptr<sql::PreparedStatement> pStmt{db->prepareStatement(
        "INSERT INTO AccessTokens (`grant`, `token`) VALUES (?, ?)")};

    pStmt->setInt(1, access_token.grant_token);
    pStmt->setUInt64(2, access_token.token);

    pStmt->executeUpdate();
    pStmt->close();
  } catch (sql::SQLException &e) {
    std::cerr << "Couldn't connect to MySQL DB." << std::endl;
    std::string c = "500 - Internal error";
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content(c, "text/plain");
    return;
  }

  // Access token has been generated and successfully inserted into the DB,
  // we must now serve it to the client.
  res.status = httplib::StatusCode::OK_200;
  res.set_header("Cache-Control", "no-store");
  res.set_header("Pragma", "no-cache");
  res.set_content(nlohmann::json{{"access_token", access_token.token},
                                 {"token_type", "Bearer"},
                                 {"expires_in", ACCESS_TOKEN_EXPIRY_TIME}}
                      .dump(),
                  "application/json");
}
