ROOTPATH=$PWD

cd $ROOTPATH/malware-win/train/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)
