
#include "api/api.hpp"
#include <httplib.h>

void f(const httplib::Request &req, httplib::Response &res) {
  res.set_content("Hello world from AuthCat!", "text/plain");
}

int main() {
  nathcat::api::Server s;
  s.registerEndpoint({"/", {f, nullptr}});

  s.listen("0.0.0.0", 8080);
}
