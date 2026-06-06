cmake_minimum_required(VERSION 3.31.11)

project(AuthCat-Server)

add_subdirectory(libs)

add_executable(AuthCat-Server src/main.cpp)

target_sources(AuthCat-Server PUBLIC
  src/User.cpp
  src/auth_server.cpp
)

target_include_directories(AuthCat-Server PUBLIC
  include
  libs/bcrypt/include
  libs/apiserver/include
  libs/json/include
)

target_link_libraries(AuthCat-Server PUBLIC
  apiserver
  bcrypt
  nlohmann_json::nlohmann_json
)

project(AuthCat-Client)

add_library(AuthCat-Client SHARED
  src/User.cpp
  src/auth_client.cpp
)

target_include_directories(AuthCat-Client PUBLIC
  include
  libs/bcrypt/include
  libs/apiserver/include
  libs/json/include
)

target_link_libraries(AuthCat-Client PUBLIC
  apiserver
  bcrypt
  nlohmann_json::nlohmann_json
)

