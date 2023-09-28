ROOTPATH=$PWD

cd $ROOTPATH/malware-win/train/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)

cd $ROOTPATH/malware-win/small_train/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)

cd $ROOTPATH/malware-win/small_train_client1/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)

cd $ROOTPATH/malware-win/small_train_client2/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)

cd $ROOTPATH/malware-win/small_train_client3/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)

cd $ROOTPATH/malware-win1/train/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)

cd $ROOTPATH/malware-win1/small_train/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)

cd $ROOTPATH/malware-win2/train/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)

cd $ROOTPATH/malware-win2/small_train/

for i in */; do zip -0 -r "${i%/}.zip" "$i" & done; wait
shopt -s extglob
rm -r !(*.zip)


