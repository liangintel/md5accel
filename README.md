This is the library used to wrap QAT hash functionality and ease the use of QAT.

Steps to use:
* Download QAT package from 01.org. e.g.
  https://01.org/sites/default/files/downloads/qat1.7.l.4.10.0-00014.tar.gz
* Extract the package into a folder, e.g. /qat
* Follow QAT manual to install and configure QAT Mainly:
  - export ICP_ROOT=/qat
  - ./configure
  - make 
  - make install
* git clone this repo and put to: e.g.
  /qat/quickassist/lookaside/access_layer/src/sample_code/functional/sym/qat_hash
* make
  You can find libqat_hash.so and qat_hash.h in this folder and these are
  what APPs such as MinIO needs

