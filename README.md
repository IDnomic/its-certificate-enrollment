# its-certificate-enrollment
ITS (Intelligent Transport Systems) certificate enrollment facilities
README.md
```
cmake -DCMAKE_INSTALL_PREFIX=/tmp/usr ..
make
make install
```
```
rm -rf ./_builds
cmake -H. -B_builds -DCMAKE_INSTALL_PREFIX:PATH=/tmp/its-pki-lib/ -DCMAKE_BUILD_TYPE=Debug
cmake --build ./_builds/
```

# -DCMAKE_BUILD_TYPE=Release -DCODE_COVERAGE=ON

# if(CMAKE_BUILD_TYPE STREQUAL "coverage" OR CODE_COVERAGE)
