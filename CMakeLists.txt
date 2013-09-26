project(mod_authn_persona)

add_executable(mod_authn_persona main.cpp)

install(TARGETS mod_authn_persona RUNTIME DESTINATION bin)
