#define AUTHCAT_CLIENT_MODE
#include <AuthCat/auth.hpp>
#include <bcrypt.h>
#include <httplib.h>
#include <memory>
using namespace nathcat::auth;

namespace nathcat {
namespace auth {
void from_json(const nlohmann::json &j, struct ClientConfig &conf) {
  j.at("hostUrl").get_to(conf.hostUrl);
}

void to_json(nlohmann::json &j, const Credentials &c) {
  j = nlohmann::json{{"username", c.username}, {"password", c.password}};
}

} // namespace auth
} // namespace nathcat

User nathcat::auth::authenticate(Credentials &creds) {
  httplib::Client cli(clientConfig.hostUrl);

  nlohmann::json body = creds;
  if (auto res =
          cli.Post("/sso/try-login.php", body.dump(), "application/json")) {
    if (res->status == httplib::StatusCode::OK_200) {
      nlohmann::json result = nlohmann::json::parse(res->body);

      std::string status = "";
      result.at("status").get_to(status);

      if (status == "success") {
        return result.at("user").get<User>();
      } else {
        throw AuthFailed();
      }
    } else {
      throw AuthFailed();
    }
  } else {
    throw res.error();
  }
}

User nathcat::auth::authenticate(Credentials_Token &creds) {
  httplib::Client cli(clientConfig.hostUrl);

  std::string cookie = "AuthCat-SSO=";
  cookie.append(creds.token);

  httplib::Headers headers = {{"Cookie", cookie}};

  if (auto res = cli.Get("/sso/get-session.php")) {
    if (res->status == httplib::StatusCode::OK_200) {
      if (res->body == "{}") {
        throw AuthFailed();
      }

      nlohmann::json result = nlohmann::json::parse(res->body);

      return result.get<User>();
    } else {
      throw AuthFailed();
    }
  } else {
    throw res.error();
  }
}

std::vector<User> __results_as_list(nlohmann::json &results) {
  std::vector<User> r;

  for (nlohmann::json::iterator it = results.begin(); it != results.end();
       ++it) {
    r.push_back((*it).get<User>());
  }

  return r;
}

std::vector<User> __user_search(nlohmann::json &body) {
  httplib::Client cli(clientConfig.hostUrl);

  nlohmann::json resBody;
  if (auto res =
          cli.Post("/sso/user-search.php", body.dump(), "application/json")) {
    if (res->status == httplib::StatusCode::OK_200) {
      resBody = nlohmann::json::parse(res->body);
      if (resBody.at("status").get<std::string>() == "success") {
        return __results_as_list(body.at("results"));

      } else {
        throw NotFound();
      }
    } else {
      throw NotFound();
    }
  } else {
    throw res.error();
  }
}

User nathcat::auth::getById(int id) {
  nlohmann::json body;
  body["id"] = id;

  std::vector<User> r = __user_search(body);
  if (r.size() == 1) {
    return r[0];
  } else {
    throw NotFound();
  }
}

std::vector<User> nathcat::auth::searchByUsername(std::string username) {
  nlohmann::json body;
  body["username"] = username;

  return __user_search(body);
}

std::vector<User> nathcat::auth::searchByFullName(std::string fullName) {
  nlohmann::json body;
  body["fullName"] = fullName;

  return __user_search(body);
}
