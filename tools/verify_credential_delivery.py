#!/usr/bin/env python3
"""Verify the firmware-owned credential delivery snapshot and dependencies."""
import hashlib
import json
from pathlib import Path
import runpy

import verify_device_credential

FILES={
 'contract.json':'82a67a801087863d3d766c82b5b3833206881e1b2ef0cb736d608e7ee143c323',
 'policy.py':'2b9b2be204227c0083ec1b847035d2f7c41dd54a2516e7f7dd50ac0d74fabfc6',
 'proof.mjs':'5815537887d9a98dd4aa543a942ff975a81ab4b074158dadba2af2e0370face2',
 'response.schema.json':'6ee7587d1bb18da144ff158da62790dab1b27b9282800355a152d84c549aaa8f',
 'status.schema.json':'89013a49aef16f51de79ceb8f5f180b326cb748d20473300fdd4a91b3b5acaf7',
 'vectors.json':'2965f9ad1c0d6cd0d669b1e92939dd42865ac3dbc7d72efabb10b71b62d88680'}
USB_FILES={
 'contract.json':'62414d301a437608c09f7693d06ad3167a6ae7f60d0c9e638153a0f98d0947c4',
 'proof.mjs':'e2738b810a1433190701788ed1940d7cb784702ef6af7f6c737ad6cc1fe292ab',
 'response.schema.json':'9e3af63f9b05ed41bb50011b134b7f7fa6d3d202b2df5203e568333a00c955e1',
 'vectors.json':'f4d7fd19a33e60883d60886c4ec10a46b1d37a2fde78a632038d902dabbc9361'}
DEVICE_FILES={
 'codec.py':'69aa7463b5bf22e2847008d721bf64d66493710c2b5b3c38e263c05ac512e752',
 'credential.schema.json':'b7234741815c4ed0cc8f2b7e7df781b64a79789ea889644602663f3ed06ed9dc',
 'profile.json':'5ca10b68f9615c205670ba0527e3d6b81ead3b46a6b4462f8d11cae3ddd73638',
 'reference.mjs':'9c31012962656abe57911262ba8a5066a453ee4c0a0682a4a6240ac583903578',
 'vectors.json':'b17775838b416bb32a933a08a3f2090b5319d1dfe7105544a7873b26e5964dee'}

def verify(root):
    root=Path(root).resolve();path=root/'credential-delivery.lock.json'
    if path.is_symlink():raise ValueError('Invalid delivery pin')
    pin=json.loads(path.read_text())
    required={'profile','version','source_repository','path','requires_device_credential_files_sha256',
              'requires_usb_provisioning_files_sha256','files'}
    if (set(pin)!=required or pin['profile']!='octatrace-credential-delivery' or
        type(pin['version']) is not int or pin['version']!=1 or pin['source_repository']!='octatrace-firmware' or
        pin['path']!='vendor/credential-delivery' or pin['files']!=FILES or
        pin['requires_device_credential_files_sha256']!=DEVICE_FILES or
        pin['requires_usb_provisioning_files_sha256']!={'contracts/usb-provisioning/'+name:digest for name,digest in USB_FILES.items()}):
        raise ValueError('Unsupported delivery pin')
    device_path=root/'device-credential.lock.json'
    if device_path.is_symlink():raise ValueError('Invalid device credential pin')
    device=json.loads(device_path.read_text())
    if device['files']!=DEVICE_FILES:raise ValueError('Device credential dependency mismatch')
    verify_device_credential.verify(root)
    usb_path=root/'usb-provisioning.lock.json'
    if not usb_path.exists():usb_path=root/'vendor/usb-provisioning.lock.json'
    if usb_path.is_symlink():raise ValueError('Invalid USB provisioning pin')
    usb=json.loads(usb_path.read_text())
    if (len(usb['files'])!=len(USB_FILES) or {Path(name).name:digest for name,digest in usb['files'].items()}!=USB_FILES or
        usb.get('format')!='octatrace-usb-provisioning' or usb.get('version')!=1):
        raise ValueError('USB provisioning dependency mismatch')
    usb_folder=root/'vendor/usb-provisioning'
    if usb_folder.exists():
        if usb_folder.is_symlink() or {p.name for p in usb_folder.iterdir() if p.is_file()}!=set(USB_FILES):
            raise ValueError('Invalid USB provisioning inventory')
        for name,digest in USB_FILES.items():
            item=usb_folder/name
            if item.is_symlink() or hashlib.sha256(item.read_bytes()).hexdigest()!=digest:
                raise ValueError('USB provisioning checksum mismatch')
    folder=root/pin['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()}!=set(FILES):
        raise ValueError('Invalid delivery inventory')
    for name,digest in FILES.items():
        item=folder/name
        if item.is_symlink() or hashlib.sha256(item.read_bytes()).hexdigest()!=digest:raise ValueError('Delivery checksum mismatch')
    contract=json.loads((folder/'contract.json').read_text());vector=json.loads((folder/'vectors.json').read_text())
    if (contract['format']!=pin['profile'] or contract['version']!=1 or contract['max_credential_bytes']!=271 or
        contract['max_chunk_bytes']!=96 or contract['proof_max_bytes']!=494 or contract['deadline_ms']!=30000 or
        vector['synthetic_only'] is not True):raise ValueError('Delivery contract mismatch')
    policy=runpy.run_path(str(folder/'policy.py'));frame=vector['frame']
    if policy['message'](frame).decode('ascii')!=vector['message_ascii']:raise ValueError('Delivery transcript mismatch')
    policy['verify'](frame,frame['id'],vector['expected'])
    return {'profile':pin['profile'],'version':1,'scope':'volatile verification only'}

if __name__=='__main__':print(json.dumps(verify(Path(__file__).resolve().parents[1]),sort_keys=True))
