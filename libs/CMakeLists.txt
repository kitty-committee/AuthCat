if(NOT DEFINED CLIENTBUILD)
  add_subdirectory(apiserver)
else()
  add_subdirectory(apiserver/libs/httplib)
endif()

add_subdirectory(bcrypt)

add_subdirectory(json)
