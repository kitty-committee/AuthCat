#include <AuthCat/db/User.hpp>
#include <api/sql.hpp>
#include <nlohmann/json.hpp>
using namespace nathcat::auth;

namespace nathcat {
namespace auth {
void from_json(const nlohmann::json &j, User &u) {
  u = {j.at("id").get<int>(),
       j.at("username").get<std::string>(),
       j.at("password").get<std::string>(),
       j.at("email").get<std::string>(),
       j.at("fullName").get<std::string>(),
       j.at("pfpPath").get<std::string>(),
       j.at("verified").get<bool>()};
}

void from_json(const nlohmann::json &j, User_NoSensitiveData &u) {
  u = {j.at("id").get<int>(), j.at("username").get<std::string>(),
       j.at("fullName").get<std::string>(), j.at("pfpPath").get<std::string>(),
       j.at("verified").get<bool>()};
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
