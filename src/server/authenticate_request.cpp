#include "AuthCat/auth.hpp"
#include "api/sql.hpp"
#include "jdbc/cppconn/prepared_statement.h"
#include "jdbc/cppconn/resultset.h"
#include <AuthCat/oauth.hpp>
using namespace nathcat::auth;

User nathcat::auth::authenticate_request(const httplib::Request &req) {
  // Check if the authorization header is present
  if (!req.has_header("Authorization"))
    throw AuthFailed();

  // Get the token from the header
  std::string auth_header = req.get_header_value("Authorization");
  std::smatch match;

  if (!std::regex_match(auth_header, match, util::bearer_token_auth_regex))
    throw AuthFailed();

  std::string token = match[1];
  uint64_t token_int = 0;
  std::istringstream(token) >> std::hex >> token_int;

  // Use the token to get the user data
  std::unique_ptr<sql::Connection> db;
  db = std::unique_ptr<sql::Connection>{nathcat::auth::driver->connect(
      auth::serverConfig.dbUrl, auth::serverConfig.dbUsername,
      auth::serverConfig.dbPassword)};
  db->setSchema(OAUTH_DB_NAME);

  std::unique_ptr<sql::PreparedStatement> stmt{db->prepareStatement(
      "SELECT Users.* FROM AccessTokens JOIN AuthGrants, Users ON "
      "AccessTokens.`grant` = Authgrants.`token` AND AuthGrants.`user` = "
      "Users.`id` WHERE AccessTokens.`token` = ?")};
  stmt->setInt64(1, token_int);

  std::unique_ptr<sql::ResultSet> rs{stmt->executeQuery()};

  User u = nathcat::sqlwrapper::fromRow<User>(rs);
  rs->close();
  stmt->close();
  db->close();

  return u;
}
