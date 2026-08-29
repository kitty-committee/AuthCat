#include "AuthCat/auth.hpp"
#include "jdbc/cppconn/exception.h"
#include <AuthCat/oauth.hpp>
#include <httplib.h>
using namespace nathcat::auth;

void nathcat::auth::user_data_endpoint(const httplib::Request &req,
                                       httplib::Response &res) {
  User u;
  try {
    u = authenticate_request(req);
  } catch (sql::SQLException &e) {
    std::cerr << "MySQL Exception: " << e.what() << std::endl;
    std::string c = "500 - Internal error";
    res.status = httplib::StatusCode::InternalServerError_500;
    res.set_content(c, "text/plain");
    return;
  } catch (AuthFailed &e) {
    std::cerr << "Request not authenticated." << std::endl;
    res.status = httplib::StatusCode::Unauthorized_401;
    res.set_header("WWW-Authenticate", "Bearer");
    return;
  }

  res.status = httplib::StatusCode::OK_200;
  nlohmann::json j(u);
  j.erase("password");
  res.set_content(j.dump(), "application/json");
}
