
#include "AuthCat/auth.hpp"
#include <AuthCat/oauth.hpp>
#include <httplib.h>

void test(const httplib::Request &req, httplib::Response &res) {
  std::cout << "Test got request" << std::endl;

  res.status = httplib::OK_200;
  res.set_content("thank you :3", "text/plain");
  return;
}

int main() {
  // Get the server config
  nathcat::auth::serverConfig =
      nathcat::auth::getConfig<struct nathcat::auth::ServerConfig>(
          "Assets/server_conf.json");

  // Init RNG
  nathcat::auth::rng = (cryptorand *)malloc(sizeof(cryptorand));
  cryptorand_init(nathcat::auth::rng);

  // Set up server endpoints
  nathcat::api::Server s;
  s.registerEndpoints(
      {{"/auth", {nathcat::auth::auth_endpoint, nullptr}},
       {"/auth/form", {nullptr, nathcat::auth::auth_form_endpoint}}});

  s.registerEndpoint({"/test", {test, nullptr}});

  // Start server
  s.listen("0.0.0.0", 8080);
}
