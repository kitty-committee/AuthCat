#ifndef _USER
#define _USER

#include <AuthCat/db/User.hpp>
#include <api/sql.hpp>
#include <nlohmann/json.hpp>
using namespace nathcat::auth;

namespace nathcat {
namespace auth {
void from_json(const nlohmann::json &j, User &u) {
  j.at("id").get_to(u.id);
  j.at("username").get_to(u.username);
  j.at("email").get_to(u.email);
  j.at("fullName").get_to(u.fullName);
  j.at("password").get_to(u.password);
  j.at("pfpPath").get_to(u.pfpPath);
  j.at("verified").get_to(u.verified);
}

void from_json(const nlohmann::json &j, User_NoSensitiveData &u) {
  j.at("id").get_to(u.id);
  j.at("username").get_to(u.username);
  j.at("fullName").get_to(u.fullName);
  j.at("pfpPath").get_to(u.pfpPath);
  j.at("verified").get_to(u.verified);
}
} // namespace auth
} // namespace nathcat

template <>
User nathcat::sqlwrapper::fromRow<User>(std::unique_ptr<sql::ResultSet> &res) {
  return {res->getInt("id"),          res->getString("username"),
          res->getString("password"), res->getString("email"),
          res->getString("fullName"), res->getString("pfpPath"),
          res->getBoolean("verified")};
}

template <>
User_NoSensitiveData nathcat::sqlwrapper::fromRow<User_NoSensitiveData>(
    std::unique_ptr<sql::ResultSet> &res) {
  return {res->getInt("id"), res->getString("username"),
          res->getString("fullName"), res->getString("pfpPath"),
          res->getBoolean("verified")};
}
#endif
