#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "duckchain::Crypto" for configuration ""
set_property(TARGET duckchain::Crypto APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(duckchain::Crypto PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "CXX"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libduckchain_crypto.a"
  )

list(APPEND _cmake_import_check_targets duckchain::Crypto )
list(APPEND _cmake_import_check_files_for_duckchain::Crypto "${_IMPORT_PREFIX}/lib/libduckchain_crypto.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
