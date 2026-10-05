#include "AuthCat/auth.hpp"
#include "api/sql.hpp"
#include "jdbc/cppconn/exception.h"
#include "jdbc/cppconn/prepared_statement.h"
#include "jdbc/cppconn/resultset.h"
#include <AuthCat/oauth.hpp>
#include <exception>
#include <httplib.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
using namespace nathcat::auth;

void nathcat::auth::user_data_endpoint(const httplib::Request &req,
                                       httplib::Response &res) {
  User u;
  bool is_authenticated = false;
  try {
    u = authenticate_request(req);
    is_authenticated = true;
  } catch (sql::SQLException &e) {
    std::cerr << "MySQL Exception: " << e.what() << std::endl;
    std::string c = "500 - Internal error";
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content(c, "text/plain");
    return;
  } catch (AuthFailed &e) {
    is_authenticated = false;
  }

  if (req.has_param("id") || req.has_param("username")) {
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

    int id;
    bool use_id = false;
    try {
      if (req.has_param("id")) {
        id = std::stoi(req.get_param_value("id"));
        use_id = true;
      }
    } catch (std::exception &e) {
      res.status = httplib::StatusCode::BadRequest_400;
      res.set_content("Missing or invalid parameter 'id'", "text/plain");
      return;
    }

    std::string username;
    bool use_username = false;
    if (req.has_param("username")) {
      username = req.get_param_value("username");
      use_username = true;
    }

    std::string query = "SELECT * FROM Users WHERE ";
    if (use_id && !use_username)
      query.append("`id` = ?");
    else if (use_username && !use_id)
      query.append("`username` = ?");
    else
      query.append("`id` = ? AND `username` = ?");

    try {
      std::unique_ptr<sql::PreparedStatement> stmt{db->prepareStatement(query)};

      if (use_id && !use_username)
        stmt->setInt(1, id);
      else if (use_username && !use_id)
        stmt->setString(1, username);
      else {
        stmt->setInt(1, id);
        stmt->setString(2, username);
      }

      std::unique_ptr<sql::ResultSet> rs{stmt->executeQuery()};

      nlohmann::json users(sqlwrapper::toArray<User>(rs));

      for (auto it = users.begin(); it != users.end(); it++) {
        it.value().erase("password");
        it.value().erase("email");
      }

      res.status = httplib::StatusCode::OK_200;
      res.set_content(users.dump(), "application/json");
      return;
    } catch (sql::SQLException &e) {
      res.status = httplib::StatusCode::InternalServerError_500;
      res.set_content("Failed to get users from DB!", "text/plain");
      return;
    }

  } else {
    if (!is_authenticated) {
      res.status = httplib::StatusCode::Unauthorized_401;
      res.set_header("WWW-Authenticate", "Bearer");
      return;
    }

    res.status = httplib::StatusCode::OK_200;
    nlohmann::json j(u);
    j.erase("password");
    res.set_content(j.dump(), "application/json");
  }
}
