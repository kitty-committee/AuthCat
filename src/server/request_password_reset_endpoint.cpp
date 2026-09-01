#include "jdbc/cppconn/exception.h"
#include "jdbc/cppconn/prepared_statement.h"
#include <AuthCat/oauth.hpp>
#include <httplib.h>
using namespace nathcat::auth;

void nathcat::auth::request_password_reset_endpoint(const httplib::Request &req,
                                                    httplib::Response &res) {
  if (!req.has_param("email")) {
    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("Missing email", "text/plain");
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

  // Call the password reset routine
  try {
    auto stmt = std::unique_ptr<sql::PreparedStatement>{
        db->prepareStatement("CALL request_password_reset(?);")};
    stmt->setString(1, req.get_param_value("email"));
    stmt->executeUpdate();
    stmt->close();
  } catch (sql::SQLException &e) {
    std::cerr << "Failed to execute request password reset routine. "
              << e.what() << std::endl;
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content("500 - Internal error", "text/plain");
    return;
  }

  res.status = httplib::StatusCode::OK_200;
  res.set_content("OK", "text/plain");
}
