cmake_minimum_required(VERSION 3.31.11)

if(NOT DEFINED CLIENTBUILD)

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

else()

  project(AuthCat-Client)

  add_subdirectory(libs)

  add_library(AuthCat-Client STATIC
  src/User_client.cpp
  src/auth_client.cpp
)

  target_include_directories(AuthCat-Client PUBLIC
  include
  libs/bcrypt/include
  #libs/apiserver/include
  libs/json/include
  libs/apiserver/libs/httplib
)

  target_link_libraries(AuthCat-Client PUBLIC
  #apiserver
  bcrypt
  nlohmann_json::nlohmann_json
  #httplib
)

endif()

