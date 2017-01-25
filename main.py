import falcon
import json
import logging
import os
import requests
from sh import mkfs, mkdir, mountpoint, mount, umount, ls, ErrorReturnCode, ErrorReturnCode_1, ErrorReturnCode_32
import sys
from time import sleep
from wsgiref import simple_server

loglevel = logging.getLevelName(os.getenv('REMORA_LOG_LEVEL', 'INFO'))
logformat = logging.Formatter('%(asctime)s - %(name)s - %(threadName)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logformat)
ch.setLevel(loglevel)
logger = logging.getLogger('Remora')
logger.setLevel(loglevel)
logger.addHandler(ch)

do_url = "https://api.digitalocean.com/v2"
do_token = os.getenv('DO_TOKEN', False)
if not do_token:
    logger.error('Remora require Digital Ocean API authentication token to work. Specify it in "DO_TOKEN" environment '
                 'variable.')
    exit(2)
do_header = {'Content-Type': 'application/json',
             'Authorization': 'Bearer {}'.format(do_token)}


class DigitalOceanDroplet(object):
    def __init__(self, droplet_hostname=None, droplet_id=None):
        self.hostname = droplet_hostname
        self.id = droplet_id
        self.volume_ids = []
        self.region = None
        self.public_ip_address = None
        self.private_ip_address = None
        self.get_droplet_info()

    def get_droplet_info(self):
        if not self.id and not self.hostname:
            logger.debug('Not droplet ID or hostname provided, using Digital Ocean metadata to get ID')
            r = requests.get('http://169.254.169.254/metadata/v1/id')
            if r.status_code in [200, 201, 202, 204]:
                self.id = r.text
                logger.debug('Found ID {} using Digital Ocean metadata'.format(self.id))
            else:
                logger.error('Failed to get ID from Digital Ocean metadata and no hostname provided.')
                return False
        if self.id:
            r = requests.get(do_url+'/droplets/'+str(self.id), headers=do_header)
        else:
            r = requests.get(do_url+'/droplets?tag_name='+self.hostname, headers=do_header)
        if r.status_code in [200, 201, 202, 204]:
            try:
                if r.json().get('droplets'):
                    tmp_droplet = r.json()['droplets'][0]
                else:
                    tmp_droplet = r.json()['droplet']
            except KeyError:
                logger.error('Failed parsing Digital Ocean response')
                logger.debug(r.json())
                return False
            logger.debug('Found {} / {} droplet in Digital Ocean'.format(self.id, self.hostname))
            self.id = tmp_droplet['id']
            self.volume_ids = tmp_droplet['volume_ids']
            self.region = tmp_droplet['region']['slug']
            if 'private_networking' in tmp_droplet['features']:
                self.private_ip_address = (network for network in tmp_droplet['networks']['v4']
                                           if network['type'] == 'private').next()['ip_address']
            self.public_ip_address = (network for network in tmp_droplet['networks']['v4']
                                      if network['type'] == 'public').next()['ip_address']
            return True
        else:
            logger.error('Failed to get Droplet information by ID: {} or Name: {}'.format(self.id, self.hostname))
            logger.debug('HTTP status: {}'.format(r.status_code))
            logger.debug('HTTP response: {}'.format(r.text))
            self.id = False
            return False


class DigitalOceanVolume(object):
    def __init__(self, volume_name, region):
        logger.debug('Initializing volume {} in {}'.format(volume_name, region))
        self.name = volume_name
        self.region = region
        self.new_volume = False
        self.id = None
        self.droplet_ids = []
        self.description = None
        self.size_gigabytes = None
        self.size = int(os.getenv('REMORA_VOLUME_SIZE', '10'))
        self.snapshot_id = os.getenv('REMORA_SNAPSHOT_ID', False)
        self.mount_point = os.getenv('REMORA_MOUNTS_PATH', '/mnt') + '/' + self.name
        self.device_name = '/host/dev/disk/by-id/scsi-' + '0' + 'DO_Volume_' + self.name
        self.get_volume_info()

    def get_volume_info(self):
        logger.debug('Looking for the volume in Digital Ocean')
        r = requests.get(do_url+'/volumes?name='+self.name+'&region='+self.region, headers=do_header)
        if r.status_code in [200, 201, 202, 204]:
            if r.json()['volumes']:
                logger.debug('Found the volume {}, Digital Ocean id {}'.format(self.name, self.id))
                volume = r.json()['volumes'][0]
                self.id = volume['id']
                self.droplet_ids = volume['droplet_ids']
                self.description = volume['description']
                self.size_gigabytes = volume['size_gigabytes']
                return True
            else:
                logger.debug('Volume {} wasn\'t found in Digital Ocean'.format(self.name))
                return self.create_new_volume()
        else:
            logger.error('Failed to get volume {} info'.format(self.name))
            logger.debug('HTTP status: {}'.format(r.status_code))
            logger.debug('HTTP response: {}'.format(r.text))
            return False

    def create_new_volume(self):
        do_data = {
            'size_gigabytes': self.size,
            'name': self.name,
            'description': 'Remora Auto-generated volume',
            'region': self.region
        }
        logger.debug('Creating new volume in Digital Ocean {}'.format(do_data))
        if self.snapshot_id:
            logger.debug('Creating volume {} from Snapshot {}'.format(self.name, self.snapshot_id))
            do_data['snapshot_id'] = self.snapshot_id
        r = requests.post(do_url+'/volumes', headers=do_header, json=do_data)
        if r.status_code in [200, 201, 202, 204]:
            logger.debug('Volume {} was created successfully with id {}'.format(self.name, self.snapshot_id))
            volume = r.json()['volume']
            self.id = volume['id']
            self.droplet_ids = volume['droplet_ids']
            self.description = volume['description']
            self.size_gigabytes = volume['size_gigabytes']
            self.new_volume = True
            sleep(3)
            return True
        else:
            logger.error('Failed to create new volume {}'.format(self.name))
            logger.debug('HTTP status: {}'.format(r.status_code))
            logger.debug('HTTP response: {}'.format(r.text))
            return False

    def attach_to_droplet(self, recurring=False):
        do_data = {
            'type': 'attach',
            'droplet_id': droplet.id,
            'region': self.region
        }
        logger.debug('Attaching volume {} to droplet {} at {} in Digital Ocean'.format(self.name, droplet.id,
                                                                                       droplet.region))
        r = requests.post(do_url+'/volumes/'+self.id+'/actions', headers=do_header, json=do_data)
        if r.status_code in [200, 201, 202, 204]:
            logger.debug('Volume {} was attached to {} in Digital Ocean'.format(self.name, droplet.id))
            return True
        elif not recurring and r.status_code == 422:
            logger.warning('Volume {} is busy, retrying - {}'.format(self.name, r.json()['message']))
            return self.attach_to_droplet(True)
        else:
            logger.error('Failed to attach volume {} to droplet {}'.format(self.name, droplet.id))
            logger.debug('HTTP status: {}'.format(r.status_code))
            logger.debug('HTTP response: {}'.format(r.text))
            return False

    def detach_from_droplet(self):
        do_data = {
            'type': 'detach',
            'droplet_id': droplet.id,
            'region': self.region
        }
        logger.debug('Detaching volume {}({}) from droplet {} - {}'.format(self.name, self.id, droplet.id,
                                                                           do_data))
        r = requests.post(do_url+'/volumes/'+self.id+'/actions', headers=do_header, json=do_data)
        if r.status_code in [200, 201, 202, 204]:
            logger.debug('Volume {} was detached from {} in Digital Ocean'.format(self.name, droplet.id))
            return True
        else:
            logger.error('Failed to detach volume {} from droplet {}'.format(self.name, droplet.id))
            logger.debug('HTTP status: {}'.format(r.status_code))
            logger.debug('HTTP response: {}'.format(r.text))
            return False

    def detach_from_droplets(self):
        logger.debug('Detaching volume {} from {} droplets'.format(self.name, len(self.droplet_ids)))
        for tmp_droplet_id in self.droplet_ids:
            tmp_droplet = DigitalOceanDroplet(droplet_id=str(tmp_droplet_id))
            if tmp_droplet.private_ip_address:
                ip_address = tmp_droplet.private_ip_address
                logger.debug('Using private IP address {}'.format(tmp_droplet.private_ip_address))
            else:
                ip_address = tmp_droplet.public_ip_address
                logger.debug('Using public IP address {}'.format(tmp_droplet.private_ip_address))
            if os.getenv('REMORA_SSL', False):
                r_proto = 'https://'
            else:
                r_proto = 'http://'
            try:
                r = requests.delete(r_proto+ip_address+':7070/volume/'+self.name, headers=do_header)
            except requests.ConnectionError:
                if tmp_droplet.private_ip_address:
                    logger.warning('Failed to connect {}. Trying with droplet public ip address {}'.
                                   format(ip_address, tmp_droplet.public_ip_address))
                    try:
                        r = requests.delete(r_proto+tmp_droplet.public_ip_address+':7070/volume/'+self.name,
                                            headers=do_header)
                    except requests.ConnectionError:
                        logger.error('Failed to connect to {}. Check Remora API is running there.'.
                                     format(tmp_droplet.public_ip_address))
                        return False
                else:
                    logger.error('Failed to connect to {}. Check Remora API is running there.'.format(ip_address))
                    return False

            if r.status_code in [200, 201, 202, 204]:
                logger.debug('Successfully detached {} from {}'.format(self.name, tmp_droplet.id))
                return True
            else:
                logger.error('Failed to detach from {}'.format(tmp_droplet.id))
                logger.debug('HTTP status: {}'.format(r.status_code))
                logger.debug('HTTP response: {}'.format(r.text))
                return False

    def create_filesystem(self):
        filesystem = os.getenv('REMORA_DEFAULT_FILESYSTEM', 'ext4')
        logger.debug('Creating {} filesystem on {}'.format(filesystem, self.name))
        try:
            mkfs('-t', filesystem, self.device_name)
        except ErrorReturnCode as err:
            logger.error('Failed to create {} filesystem on {}'.format(filesystem, self.name))
            logger.debug(err)
            return False
        return True

    def mount_volume(self):
        logger.debug('Mounting {} to {} on droplet {}'.format(self.device_name, self.mount_point, droplet.id))
        try:
            logger.debug('Waiting a bit to for disk to be attached')
            sleep(5)
            ls('-l', self.device_name)
        except ErrorReturnCode:
            pass
        if self.new_volume:
            logger.debug('{} is brand new volume, creating filesystem on it'.format(self.name))
            if not self.create_filesystem():
                return False
        try:
            mkdir('-p', self.mount_point)
        except ErrorReturnCode as err:
            logger.error('Failed creating mount point {}'.format(self.mount_point))
            logger.debug(err)
            return False
        try:
            mount(self.device_name, self.mount_point)
        except ErrorReturnCode_32 as err:
            logger.error('Can\'t mount {}, looks like it\'s has no valid filesystem or maybe it\'s partitioned'.
                         format(self.device_name))
            logger.debug(err)
            return False
        except ErrorReturnCode as err:
            logger.error('Mount failed: {}'.format(err))
            return False
        return True

    def umount_volume(self):
        logger.debug('Un mounting {} volume from droplet {}'.format(self.name, droplet.id))
        try:
            mountpoint('-q', self.mount_point)
        except ErrorReturnCode_1:
            logger.debug('Volume {} is not mounted on {}'.format(self.name, droplet.id))
            return True
        else:
            try:
                umount(self.mount_point)
            except ErrorReturnCode as err:
                logger.error('Umount failed: {}'.format(err))
                return False
        return True


class AuthMiddleware(object):
    def process_request(self, req, resp):
        token = req.get_header('Authorization')

        challenges = ['Token type="Bearer"']

        if token is None:
            raise falcon.HTTPUnauthorized('Auth token required',
                                          'Please provide an auth token as part of the request.',
                                          challenges)
        if not self._token_is_valid(token):
            raise falcon.HTTPUnauthorized('Authentication required',
                                          'The provided auth token is not valid',
                                          challenges)

    @staticmethod
    def _token_is_valid(token):
        if 'Bearer' in token:
            if token[7:] == do_token:
                logger.debug('Valid request')
                return True
        return False


class VolumeResource(object):
    # Request to attach volume and mount it
    def on_put(self, req, resp, volume_name):
        logger.debug('PUT - Volume name: {}'.format(volume_name))
        volume = DigitalOceanVolume(volume_name, droplet.region)
        if volume.id:
            if volume.droplet_ids:
                logger.debug('Volume {} is attached to droplets {}'.format(volume.name, volume.droplet_ids))
                if droplet.id in volume.droplet_ids:
                    logger.info('Volume {} is attached to this droplet {} already'.format(volume.name, droplet.id))
                else:
                    logger.info('Volume {} is not attached to this droplet {}'.format(volume.name, droplet.id))
                    if volume.detach_from_droplets():
                        if not volume.attach_to_droplet():
                            raise falcon.HTTPInternalServerError('Failed to attach volume',
                                                                 'Failed to attach {} volume to the droplet {}. See '
                                                                 'logs for more information'.format(volume.name,
                                                                                                    droplet.hostname))
                    else:
                        raise falcon.HTTPInternalServerError('Failed to detach volume',
                                                             'Failed to detach {} volume from one of the droplets '
                                                             'it\'s attached to it. See droplets logs for more'
                                                             'information'.format(volume.name))
            else:
                logger.info('Volume {} is not attached to any droplet'.format(volume.name))
                if not volume.attach_to_droplet():
                    raise falcon.HTTPInternalServerError('Failed to attach volume',
                                                         'Failed to attach {} volume to the droplet {}. See logs '
                                                         'for more information'.format(volume.name, droplet.hostname))
            if volume.mount_volume():
                if volume.new_volume:
                    resp.status = falcon.HTTP_201
                else:
                    resp.status = falcon.HTTP_200
                resp.body = json.dumps(volume.__dict__)
            else:
                raise falcon.HTTPInternalServerError('Failed to mount volume',
                                                     'Failed to mount {} volume to droplet {}. See logs for more '
                                                     'information'.format(volume.name, droplet.hostname))
        else:
            logger.error('Failed to get volume from Digital Ocean API')
            raise falcon.HTTPInternalServerError('Error getting volume information',
                                                 'Failed to get volume {} information from Digital Ocean API, check '
                                                 'logs for more information.'.format(volume_name))

    # Request to umount and detach volume
    def on_delete(self, req, resp, volume_name):
        logger.debug('DELETE - Volume name: {}'.format(volume_name))
        volume = DigitalOceanVolume(volume_name, droplet.region)
        if volume.id:
            if volume.umount_volume():
                if volume.detach_from_droplet():
                    resp.status = falcon.HTTP_200
                else:
                    raise falcon.HTTPInternalServerError('Detach failure',
                                                         'Failed to detach {} from {} in Digital Ocean API. For more '
                                                         'information see server logs.'.format(volume.name, droplet.id))
            else:
                raise falcon.HTTPInternalServerError('Un-mount failure',
                                                     'Failed to un-mount {} volume from {}. For more information see '
                                                     'logs.'.format(volume.name, droplet.id))
        else:
            logger.error('Failed to get volume from Digital Ocean API')
            raise falcon.HTTPInternalServerError('Error getting volume information',
                                                 'Failed to get volume {} information from Digital Ocean API, check '
                                                 'logs for more information.'.format(volume_name))


droplet = DigitalOceanDroplet()
if droplet.id:
    logger.debug('Droplet {} in {}'.format(droplet.id, droplet.region))
else:
    logger.error('No droplet found in Digital Ocean API. Remora API can ran only on Digital Ocean droplets')
    exit(3)
app = falcon.API(middleware=[AuthMiddleware()])
app.add_route('/volume/{volume_name}', VolumeResource())

logger.info('Starting Remora API')
httpd = simple_server.make_server('', 7070, app)
httpd.serve_forever()
