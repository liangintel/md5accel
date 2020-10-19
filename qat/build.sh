if [ -z "$1" ];
then
    echo "Need to specify a path where QAT package will be downloaded and built"
    exit
fi

CUR_DIR=`pwd`
WORK_DIR=$1/qat1.x
sudo rm -rf $WORK_DIR
mkdir $WORK_DIR
cd $WORK_DIR

#download qat package from 01.org, latest package can be found at https://01.org/intel-quickassist-technology
QAT_TAR_PKG=qat1.7.l.4.9.0-00008.tar.gz
wget https://01.org/sites/default/files/downloads/$QAT_TAR_PKG

tar -zxvf $QAT_TAR_PKG

#install dependance (only ubuntu)
sudo apt update
sudo apt install pciutils-dev libpci-dev g++ pkg-config libssl-dev -y

#compile qat library
export ICP_ROOT=$WORK_DIR
./configure
make
sudo make install

#add current user to group qat
sudo usermod -a -G qat `whoami`

#compile md5accel module
MD5DIR=$ICP_ROOT/quickassist/lookaside/access_layer/src/sample_code/functional/sym/md5accel

mkdir $MD5DIR
cp $CUR_DIR/qat_hash.c $MD5DIR/
cp $CUR_DIR/qat_hash.h $MD5DIR/
cp $CUR_DIR/qat_utils.h $MD5DIR/
cp $CUR_DIR/Makefile $MD5DIR/

cd $MD5DIR
make
echo $MD5DIR
ls -l $MD5DIR
sudo cp $MD5DIR/libqat_hash.so /usr/local/lib/
sudo ldconfig

#remove libraries from $CUR_DIR so these can be found in /usr/local/lib/
sudo rm -rf $CUR_DIR/libqat_hash.so
sudo rm -rf $CUR_DIR/libqat_s.so
sudo rm -rf $CUR_DIR/libusdm_drv_s.so

