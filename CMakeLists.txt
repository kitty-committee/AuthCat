cmake_minimum_required(VERSION 3.28.3)

if(NOT DEFINED CLIENTBUILD OR NOT CLIENTBUILD)

  project(AuthCat-Server)

  add_subdirectory(libs)

  add_executable(AuthCat-Server src/server/main.cpp)

  target_sources(AuthCat-Server PUBLIC
  src/server/User.cpp
  src/server/auth.cpp
  src/server/auth_endpoint.cpp
  src/server/auth_grant.cpp
  src/server/token_endpoint.cpp
  src/server/access_tokens.cpp
  src/server/validate_access_token_endpoint.cpp
  src/server/util.cpp
  src/server/db.cpp
  src/server/html.cpp
)

  target_include_directories(AuthCat-Server PUBLIC
  include
  libs/bcrypt/include
  libs/apiserver/include
  libs/json/include
  libs/apiserver/libs/mysql/include
  libs/cryptorand
  libs/boost-mlp/include
  libs/lexbor/source
)

  target_link_libraries(AuthCat-Server PUBLIC
  apiserver
  bcrypt
  nlohmann_json::nlohmann_json
  cryptorand
  boost_multiprecision
  #lexbor-html
  #lexbor-dom
  lexbor
)

  project(hashtest)
  add_executable(hashtest src/hashtest.cpp)
  target_include_directories(hashtest PUBLIC
    libs/bcrypt/include
  )
  target_link_libraries(hashtest PUBLIC
    bcrypt
  )

  project(regextest)
  add_executable(regextest src/regex_test.cpp)
  target_include_directories(regextest PUBLIC include)

else()

  project(AuthCat-Client)

  add_subdirectory(libs)

  add_library(AuthCat-Client STATIC
  src/client/User.cpp
  src/client/auth.cpp
  )

  target_include_directories(AuthCat-Client PUBLIC
  include
  libs/bcrypt/include
  libs/json/include
  libs/apiserver/libs/httplib
)

  target_link_libraries(AuthCat-Client PUBLIC
  bcrypt
  nlohmann_json::nlohmann_json
)

endif()

