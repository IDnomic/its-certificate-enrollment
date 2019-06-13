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
