#define AUTHCAT_CLIENT_MODE
#include <AuthCat/db/User.hpp>
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
