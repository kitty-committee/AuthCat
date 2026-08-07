#include "AuthCat/db/Credentials.hpp"
#include "jdbc/cppconn/connection.h"
#include <AuthCat/auth.hpp>
#include <AuthCat/auth_grant.hpp>
#include <AuthCat/oauth.hpp>
#include <httplib.h>
#include <memory>
#include <string>

void nathcat::auth::auth_endpoint(const httplib::Request &req,
                                  httplib::Response &res) {
  std::string c;

  std::unique_ptr<sql::Connection> db{nathcat::auth::driver->connect(
      auth::serverConfig.dbUrl, auth::serverConfig.dbUsername,
      auth::serverConfig.dbPassword)};
  db->setSchema("oauth");

  // Get query params
  if (!req.has_param("response_type") || !req.has_param("client_id")) {
    // Serve warning
    std::cerr << "Request is invalid" << std::endl;
    c = util::read_file(OAUTH_LOGIN_REQUEST_INVALID_PAGE_PATH);
    res.status = httplib::StatusCode::OK_200;
    res.set_content(c, "text/html");
    return;
  }

  try {

    // Validate client_id
    std::string client_id = req.get_param_value("client_id");
    struct client client;

    try {
      client = nathcat::auth::util::get_client(db, client_id);
    } catch (nathcat::auth::NotFound &e) {
      // Don't allow the user to login
      std::cerr << "Could not find client record" << std::endl;
      c = util::read_file(OAUTH_LOGIN_REQUEST_INVALID_PAGE_PATH);
      res.status = httplib::StatusCode::OK_200;
      res.set_content(c, "text/html");
      return;
    }

    // Serve login page
    c = nathcat::auth::util::read_file(OAUTH_LOGIN_PAGE_PATH);
    res.status = httplib::StatusCode::OK_200;
    res.set_content(c, "text/html");
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    throw e;
  }
}

void nathcat::auth::auth_form_endpoint(const httplib::Request &req,
                                       httplib::Response &res) {
  if (!req.has_param("client_id") || !req.form.has_field("username") ||
      !req.form.has_field("password")) {
    res.status = httplib::StatusCode::BadRequest_400;
    res.set_content("Malformed request", "text/plain");
    return;
  }

  std::unique_ptr<sql::Connection> db{driver->connect(
      serverConfig.dbUrl, serverConfig.dbUsername, serverConfig.dbPassword)};

  struct client client = util::get_client(db, req.get_param_value("client_id"));
  std::string username = req.form.get_field("username");
  std::string password = req.form.get_field("password");

  // Authenticate the user
  nathcat::auth::User user;
  try {
    Credentials creds{username, password};
    user = authenticate(db, creds);
  } catch (AuthFailed &e) {
    std::cerr << "Failed to authenticate user" << std::endl;
    res.status = httplib::StatusCode::Found_302;
    res.set_header("Location",
                   client.redirectionUri.append("?error=access_denied"));
    return;
  }

  // Authentication successful, create a auth grant and return it
  // TODO change the scope parameter to be something defined by the client.
  nathcat::auth::AuthGrant grantCode = create_auth_grant(user.id, {true});
}
