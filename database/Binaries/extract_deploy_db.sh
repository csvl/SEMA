ROOTPATH=$PWD

cd $ROOTPATH/malware-win/train/

unzip '*.zip'
rm -r *.zip

cd $ROOTPATH/malware-linux/

unzip '*.zip'
rm -r *.zip
