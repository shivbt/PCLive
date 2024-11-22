# PCLive: Pipelined Restoration of Application Containers for Reduced Service Downtime

Application containers are widely used in contemporary cloud computing environments.
Migration of containers across hosts provides cost-effective cloud management by
enabling improved server consolidation, load balancing and enhanced fault tolerance.
One of the primary objectives of container migration is to reduce the service downtime
of applications hosted in containers. The service downtime depends on performing
the migration activities efficiently, specifically from the time the container is
stopped on the source host till it is restored and fully functional at the destination host.

In this paper, we show that, the state-of-the-art pre-copy migration strategy for
containers using checkpoint and restore techniques (e.g., CRIU) inflates the
downtime due to its inherent limitations in the restoration procedures, particularly
for containers with large memory working set size. We propose PCLive to address
this bottleneck using a pipelined restore mechanism. Compared to the baseline CRIU
pre-copy migration, PCLive results in up to ~38.8x reduction in restoration time
which leads to a reduction of service downtime by up to ~2.7x for migration of
a container hosting the Redis key-value store over an one Gbps network. We also
present comprehensive comparative analysis of the resource cost for the proposed
solution along with additional optimizations to demonstrate that PCLive can reduce
the application downtime in a resource efficient manner leveraging its flexible
and efficient design choices.
>
> **Published in:** SoCC '24: Proceedings of the 2024 ACM Symposium on Cloud Computing<br/>
> **Author:** Shiv Bhushan Tripathi, Debadatta Mishra<br/>
> **Venue:** Redmond, WA, in the Microsoft Campus, from November 20th-22nd<br/>
> **Link:** https://doi.org/10.1145/3698038.3698545<br/>
>

## Directory Structure

<pre>
PCLive<br />
  |___ baseline: contains source codes for Vanilla CRIU and runC.<br />
  |___ pc_live: contains source codes for PCLive on top of CRIU and runC.<br />
  |___ pc_live_g: contains source codes for PCLiveG on top of CRIU and runC.<br />        
</pre>

## Installing CRIU & RunC for PCLive, PCLiveG and Baseline

To install CRIU and RunC for PCLive, PCLiveG and Baseline (Vanilla) please follow
below steps:

1. Install `CRIU` dependencies from [this link](https://medium.com/@TarunChinmai/criu-installation-f277cda14ce0).

2. Install `CRIU` from the directory **criu** (sub-directory in *pc\_live*, *pc\_live\_g* and *baseline*).

3. Follow instructions given in **runc\_installation.md** file to install `runC`.

## Live Migration of Application Container

Please follow steps listed below to perform live migration:

1. Get a base image from docker hub and extract it to some directory using
following commands:
```bash
$ pwd
/home/shiv/

$ mkdir -p shiv_containers/rootfs

$ cd shiv_containers

$ docker export $(docker run -d alpine) | tar -C rootfs -xv

# Now do ls to see the rootfs of the container.
$ ls rootfs

# Copy sample config file (*runc\_config.json*) to the shiv_containers directory
# as config.json.
$ cp /PCLive/runc_config.json config.json
```

2. Now run the container.
```bash
# To run the container, go to your rootfs directory of the container.
$ cd /home/shiv/shiv_containers

# Run the container.
$ sudo runc run container_name
```

3. Afer container starts running, live migration can be performed.

4. Use following commands to test the status of migration:
```bash
$ sudo runc list   # It will not display running containers.

# If migration is not successfull then you may have to kill the container.
$ sudo runc kill container_name KILL

# To list all the processes inside the container.
$ sudo runc ps container_name

# To execute anything from the host of container.
$ sudo runc exec container_name <shell_command>
```

5. Use below commands to get the various options provided by `CRIU` and `RunC`
for PCLive, PCLiveG, and Baseline.
```bash
criu --help
runc --help
```

### Contact

shivbt[AT]cse[DOT]iitk[DOT]ac[DOT]in
