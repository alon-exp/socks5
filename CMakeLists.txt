cmake_minimum_required(VERSION 3.10)
project(socks5-server)

aux_source_directory(. SRC_LISTS)

add_executable(server ${SRC_LISTS})