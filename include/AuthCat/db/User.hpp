#include "nlohmann/json_fwd.hpp"
#include <string>

namespace nathcat {
namespace auth {

struct User {
  int id;
  std::string username;
  std::string password;
  std::string email;
  std::string fullName;
  std::string pfpPath;
  bool verified;
};

void from_json(const nlohmann::json &j, User &u);

struct User_NoSensitiveData {
  int id;
  std::string username;
  std::string fullName;
  std::string pfpPath;
  bool verified;
};

void from_json(const nlohmann::json &j, User_NoSensitiveData &u);

} // namespace auth
} // namespace nathcat
