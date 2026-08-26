#include "AuthCat/access_tokens.hpp"
#include "AuthCat/auth.hpp"
#include "AuthCat/auth_grant.hpp"
#include "jdbc/cppconn/exception.h"
#include "jdbc/cppconn/prepared_statement.h"
#include "jdbc/cppconn/resultset.h"
#include <AuthCat/oauth.hpp>
#include <httplib.h>
#include <regex>
#include <sstream>
using namespace nathcat::auth;

void nathcat::auth::validate_access_token_endpoint(const httplib::Request &req,
                                                   httplib::Response &res) {
  if (!req.has_header("Authorization")) {
    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("{\"error\":\"invalid_request\"}", "application/json");
    return;
  }

  std::string auth_header = req.get_header_value("Authorization");
  std::smatch auth_match;
  if (!std::regex_match(auth_header, auth_match,
                        util::bearer_token_auth_regex)) {
    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("{\"error\":\"invalid_request\"}", "application/json");
    return;
  }

  std::string token = auth_match[1];
  // We have the access token string
  uint64_t token_int = 0;
  std::istringstream(token) >> std::hex >> token_int;
  // ... and now we have the integer, we can extract it from the DB

  // Attempt to open a connection to the database
  std::unique_ptr<sql::Connection> db;
  try {
    db = std::unique_ptr<sql::Connection>{nathcat::auth::driver->connect(
        auth::serverConfig.dbUrl, auth::serverConfig.dbUsername,
        auth::serverConfig.dbPassword)};
    db->setSchema(OAUTH_DB_NAME);
  } catch (sql::SQLException &e) {
    std::cerr << "Couldn't connect to MySQL DB." << std::endl;
    std::string c = "500 - Internal error";
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content(c, "text/plain");
    return;
  }

  uint64_t scope;
  uint64_t timeIssued;

  try {
    std::unique_ptr<sql::PreparedStatement> pStmt{db->prepareStatement(
        "SELECT AuthGrants.`scope` AS 'scope', AccessTokens.`timeIssued` AS "
        "'timeIssued' FROM AccessTokens JOIN AuthGrants ON "
        "AccessTokens.`grant` = AuthGrants.`token` WHERE AccessTokens.`token` "
        "= ?")};
    pStmt->setInt64(1, token_int);

    std::unique_ptr<sql::ResultSet> rs{pStmt->executeQuery()};
    pStmt->close();
    if (!rs->next()) {
      res.status = httplib::StatusCode::Unauthorized_401;
      res.set_header("WWW-Authenticate", "Bearer");
      return;
    }

    scope = rs->getInt64("scope");
    timeIssued = rs->getInt64("timeIssued");

  } catch (sql::SQLException &e) {
    std::cerr << "Couldn't retrieve access token information from DB."
              << std::endl
              << e.what() << std::endl;
    std::string c = "500 - Internal error";
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content(c, "text/plain");
    return;
  }

  // We now have the scope of the token, and the time it was issued.
  // We must validate that the token has not expired before serving the
  // scope information.
  uint64_t currentTime = util::epoch_time();
  if (currentTime > (timeIssued + ACCESS_TOKEN_EXPIRY_TIME)) {
    // Delete the access token
    try {
      std::unique_ptr<sql::PreparedStatement> pStmt{
          db->prepareStatement("DELETE FROM AccessTokens WHERE `token` = ?")};
      pStmt->setInt64(1, token_int);
      pStmt->executeUpdate();
      pStmt->close();
    } catch (sql::SQLException &e) {
      std::cerr << "Couldn't delete access token from the DB." << std::endl
                << e.what() << std::endl;
      std::string c = "500 - Internal error";
      res.status = httplib::StatusCode::InternalServerError_500;
      res.set_content(c, "text/plain");
      return;
    }

    // ... and serve a 401 error
    res.status = httplib::StatusCode::Unauthorized_401;
    res.set_header("WWW-Authenticate", "Bearer");
    return;
  }

  // At this point, the access token has been shown to be valid,
  // we can now encode the scope information and serve it to the client.
  struct Scope scope_s = extract_scope_from_auth_grant(AuthGrant{0, 0, scope});
  nlohmann::json scope_json = nlohmann::json(scope_s);

  res.status = httplib::StatusCode::OK_200;
  res.set_content(scope_json.dump(), "application/json");
}
