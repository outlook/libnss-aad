# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |v|
    v.memory = 1024
    v.cpus = 2
  end
  config.vm.box = "minimal/xenial64"
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y pkg-config libssl-dev
    curl https://sh.rustup.rs -sSf -o /tmp/rustup.sh
    chmod +x /tmp/rustup.sh
    sudo -i -u vagrant /tmp/rustup.sh -y
  SHELL
end
