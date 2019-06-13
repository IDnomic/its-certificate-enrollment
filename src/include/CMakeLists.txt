# install(DIRECTORY include/its/ DESTINATION include/its/)

file(GLOB headers "its/*.hh")

install(FILES ${headers}
	DESTINATION coucou/include/its
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)


