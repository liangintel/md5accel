This is the library used to wrap QAT hash functionality and ease the use of QAT.

Steps to use:
* cd ./qat/

* chmod +x build.sh

* Install Intel QAT driver and library
  ./build.sh ~/tmp_path_for_qat_pkg_to_compile

  Added current user to group qat, need to logout and then login Linux to take effect

* In go source code:
  import github.com/liangintel/md5accel

