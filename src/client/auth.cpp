#define CPPHTTPLIB_OPENSSL_SUPPORT
#define AUTHCAT_CLIENT_MODE
#include <AuthCat/client/auth.hpp>
#include <httplib.h>
using namespace nathcat::auth;

namespace nathcat {
namespace auth {
struct ClientConfig clientConfig = {"https://auth.nathcat.net"};

void from_json(const nlohmann::json &j, struct ClientConfig &conf) {
  j.at("hostUrl").get_to(conf.hostUrl);
}

} // namespace auth
} // namespace nathcat

User nathcat::auth::authenticate(Credentials_Token &creds) {
  httplib::Client cli(clientConfig.hostUrl);

  httplib::Headers headers = {
      {"Authorization", std::string("Bearer ").append(creds.token)}};

  if (auto res = cli.Get("/user", headers)) {
    if (res->status == httplib::StatusCode::OK_200) {

      nlohmann::json result = nlohmann::json::parse(res->body);
      return result.get<User>();
    } else {
      throw AuthFailed();
    }
  } else {
    throw res.error();
  }
}
