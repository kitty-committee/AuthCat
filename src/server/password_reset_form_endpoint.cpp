#include "AuthCat/html.hpp"
#include "api/sql.hpp"
#include "jdbc/cppconn/exception.h"
#include "jdbc/cppconn/prepared_statement.h"
#include <AuthCat/oauth.hpp>
#include <httplib.h>
using namespace nathcat::auth;

void nathcat::auth::password_reset_form_endpoint(const httplib::Request &req,
                                                 httplib::Response &res) {
  if (!req.has_param("t")) {
    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("Missing token", "text/plain");
    return;
  }

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

  std::string token = req.get_param_value("t");
  User user;
  std::unique_ptr<sql::PreparedStatement> stmt;

  try {
    stmt = std::unique_ptr<sql::PreparedStatement>{db->prepareStatement(
        "SELECT Users.* FROM PasswordResetToken JOIN Users ON "
        "PasswordResetToken.`id` = Users.`id` WHERE `token` = sha2(?, 256);")};
    stmt->setString(1, token);

    std::unique_ptr<sql::ResultSet> rs{stmt->executeQuery()};

    if (!rs->next()) {
      stmt->close();
      rs->close();
      res.status = httplib::StatusCode::BadRequest_400;
      res.set_content("Invalid token", "text/plain");
      return;
    }
    user = nathcat::sqlwrapper::fromRow<User>(rs);
    stmt->close();
    rs->close();
  } catch (sql::SQLException &e) {
    std::cerr << "Failed to get user data from the DB by password reset token. "
              << e.what() << std::endl;
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content("500 - Internal error", "text/plain");
    return;
  }

  std::string content = nathcat::html::parse_templated_html(
      std::string(AUTHCAT_HTML_ROOT).append(OAUTH_PASSWORD_RESET_PATH),
      std::unordered_map<std::string, std::string>{
          {"token", token}, {"username", user.username}});

  res.status = httplib::StatusCode::OK_200;
  res.set_content(content, "text/html");
}
