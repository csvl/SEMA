# Bash script to download Malware Bazaar based on tag


# Define tag and number of samples to download
TAG=AveMariaRAT
DOWNLOAD_LIMIT=500


# Download hash values from tag, save the SHA256 hashes
curl -XPOST -d "query=get_siginfo&signature=${TAG}&limit=${DOWNLOAD_LIMIT}" https://mb-api.abuse.ch/api/v1/ | grep sha256_hash | awk '{print $2}' > ${TAG}.raw


sed -i 's/"//g' ${TAG}.raw
sed -i 's/,//' ${TAG}.raw

# Create the hash file from the raw file
mv ${TAG}.raw ${TAG}.hash

cat ${TAG}.hash

while read h; do echo ${h}; done < ${TAG}.hash
# Download the samples using their hash vaules
while read h; do curl -XPOST -d "query=get_file&sha256_hash=${h}" -o ${h} https://mb-api.abuse.ch/api/v1/; done < ${TAG}.hash


# Unarchive the malware samples
while read h; do 7z e ${h} -p"infected"; done < ${TAG}.hash



for file in *
    do
        if file $file | grep -q "PE32"
        then
            if file $file | grep -q "Nullsoft"
            then
                rm $file
            elif file $file | grep -q "Mono/.Net"
            then
                rm $file
            else
                echo $file
            fi
        else
            rm $file
        fi
    done

# Clean up by removing the hash lists and compressed archives files
while read h; do rm ${h}; done < ${TAG}.hash
rm ${TAG}.raw
rm ${TAG}.hash
