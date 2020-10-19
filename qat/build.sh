CUR_DIR=`pwd`
sudo rm -rf qat1.x
mkdir qat1.x
cd qat1.x

#download qat package from 01.org, latest package can be found at https://01.org/intel-quickassist-technology
QAT_TAR_PKG=qat1.7.l.4.9.0-00008.tar.gz
wget https://01.org/sites/default/files/downloads/$QAT_TAR_PKG

tar -zxvf $QAT_TAR_PKG

#install dependance (only ubuntu)
sudo apt update
sudo apt install pciutils-dev libpci-dev g++ pkg-config libssl-dev

#compile qat library
export ICP_ROOT=`pwd`
./configure
make
sudo make install

#compile md5accel module
MD5DIR=$ICP_ROOT/quickassist/lookaside/access_layer/src/sample_code/functional/sym/md5accel

mkdir $MD5DIR
cp ../qat_hash.c $MD5DIR/
cp ../qat_hash.h $MD5DIR/
cp ../qat_utils.h $MD5DIR/
cp ../Makefile $MD5DIR/

cd $MD5DIR
make
echo $MD5DIR
ls -l $MD5DIR
cd $CUR_DIR
sudo cp $MD5DIR/libqat_hash.so /usr/local/lib/
sudo ldconfig

