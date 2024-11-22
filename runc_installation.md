# runC

`runC` is open source conatiner running environment. It is very lighweight. Using
runC, you can make and manage containers on your machine. `runC` must be built
with Go version 1.13 or higher.

# Pre - Requisite

1. Make sure openssh-server is installed on your linux machine and run
`ufw allow OpenSSH` to use ssh even when firewall is enabled.

2. You have `Ubuntu 20.04` as your operating system. If you have other linux
distro then the commands need to adjusted according to your os version.

3. Create an account on `Docker Hub` if you wish to create your own images
and push them to Docker Hub. **(Optional)**


# Instructions
Follow the given instructions to install `runC` on your linux machine.

## Install go and libseccomp

For that go to official go lang site and do the neccessary steps to install
`go` on your machine.
Then install `libseccomp`. On ubuntu run following

```bash
sudo apt-get install libseccomp-dev
```
> Make sure you have written below line in `/etc/profile` to make go available
> for all users.
> ```bash
> export PATH=$PATH:/usr/local/go/bin
> ```

## Install Docker

**1.** First run
```bash
sudo apt-get update
```

**2.** Then install some packages which let `apt` use packages over **HTTPS**
```bash
sudo apt install apt-transport-https ca-certificates curl software-properties-common
```

**3.** Then add the GPG key for the official Docker repository to your system
```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
```
> If it is giving some certificate error then go with following command:
> ```bash
> curl -fsSL https://download.docker.com/linux/ubuntu/gpg --insecure | sudo apt-key add -
> ```

**4.** Add the Docker repository to APT sources
```bash
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
```

**5.** Now run
```bash
sudo apt update
```

**6.** Make sure you are about to install from the Docker repo instead of the
default Ubuntu repo by seeing the **URL** output from below command:
```bash
apt-cache policy docker-ce
```

**7.** Finally, install Docker
```bash
sudo apt install docker-ce
```

**8.** Check docker status by
```bash
sudo systemctl status docker
```

**9.** If you want to avoid typing sudo whenever you run the docker command then
add your username to the docker group
```bash
sudo usermod -aG docker ${USER}
```
> The above command is for current logged in user only. If you want to add some
> one else just add _username_ instead of _${USER}_in the above command.
> Similiar changes will also go for below command also.

**10.** To apply it logout then again log back in OR type following to apply
```bash
su - ${USER}
```

**11.** Now you can check your membership with following command
```bash
id -nG
```
It will show you `your_user_name sudo docker` as output.

## Install pkg-config

To make runc please install **pkg-config** using following command
```bash
sudo apt install pkg-config
```

## Install runC

Now you are ready to install `runC` on your system. Steps are as follows

> Run `sudo su -` and become super user. If you don't become super user then
> running go will give errors while copying in during make command.

```bash
# The GOPATH is /usr/local/go/
# Go to GOPATH/src and run

mkdir github.com
```

```bash
cd github.com
mkdir opencontainers
cd opencontainers
# Copy runc source code for PCLive/ PCLiveG/ Baseline here.
# Do cd to that directory.
make
make install
```

After successul running all these command runC will be installed in
`/usr/local/sbin/runc`.
