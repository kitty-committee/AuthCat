#include "bcrypt.h"
#include "jdbc/cppconn/exception.h"
#include "jdbc/cppconn/prepared_statement.h"
#include <AuthCat/oauth.hpp>
#include <httplib.h>
using namespace nathcat::auth;

void nathcat::auth::password_reset_endpoint(const httplib::Request &req,
                                            httplib::Response &res) {
  if (!req.has_param("t") || !req.has_param("password")) {
    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("Invalid request", "text/plain");
    return;
  }

  std::string token = req.get_param_value("t");
  std::string passwordHash =
      bcrypt::generateHash(req.get_param_value("password"));

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

  try {
    std::unique_ptr<sql::PreparedStatement> stmt{
        db->prepareStatement("CALL update_password(?, ?);")};

    stmt->setString(1, token);
    stmt->setString(2, passwordHash);
    stmt->executeUpdate();
    stmt->close();
  } catch (sql::SQLException &e) {
    std::cerr << "Failed to update password. " << e.what() << std::endl;
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content("500 - Internal error", "text/plain");
    return;
  }

  res.status = httplib::StatusCode::Found_302;
  res.set_content("OK", "text/plain");
  res.set_header("Location",
                 std::string("auth?client_id=")
                     .append(OAUTH_POST_PASSWORD_RESET_LOGIN_CLIENT_ID)
                     .append("&response_type=code"));
}
