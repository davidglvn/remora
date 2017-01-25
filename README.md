# Remora
Remora is privileged Docker image that helps moving Digital Ocean volumes from one node to another.
Original it's written to work in Rancher environment to keep persistence storage between containers on any node.

# Usage
Build the image and run it on the nodes that can share the volume.
If running in Docker container make sure it's:
- running in privileged mode
- mounted /dev into /host/dev
- mounted directory for the mounts in shared mode
- required environment variables are filled

For example:
```bash
# docker run -ti --privileged -v /dev:/dev:rw -v /mnt:/mnt:shared -e DO_TOKEN=<YOUR DIGITAL OCEAN TOKEN> remora
```
## Environment variables
- DO_TOKEN - Digital Ocean API token with write permissions
- REMORA_LOG_LEVEL - Remora log level, default ```INFO```
- REMORA_VOLUME_SIZE - Volume size to create, default 10
- REMORA_SNAPSHOT_ID - New volume can be created from Digital Ocean snapshot
- REMORA_MOUNTS_PATH - Path were new mounts will be created, default ```/mnt```
- REMORA_SSL - True if Remora API using SSL certificate
- REMORA_DEFAULT_FILESYSTEM - Filesystem for new volumes, default ```ext4```
