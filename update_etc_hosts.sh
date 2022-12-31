# Restore the original hosts file
sudo cp /etc/hosts.bak /etc/hosts

# # Make a copy
# sudo cp /etc/hosts /etc/hosts.bak

echo "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'  sema-web) sema-app" | sudo tee -a /etc/hosts
