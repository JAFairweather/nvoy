// Per-instance host socket for Hive reads. The SSH key and host pin stay on the
// fleet host; only this socket directory is mounted into the recall container.
export const RECALL_SOCKET = '/run/nvoy-recall-gw/socket'

export function recallGatewayUnits(manifest) {
  if (!manifest.mayRecall || manifest.mayRecall.read.socket !== RECALL_SOCKET || !manifest.mayRecall.gatewayGid) {
    throw new Error('the recall gateway needs its fixed socket and dedicated gateway_gid')
  }
  const id = manifest.id
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(id)) throw new Error('a recall gateway needs a group-safe lowercase instance id')
  const unit = `nvoy-recall-gw-${id}`
  const group = `nvoy-recall-${id}`
  if (!/^[a-z_][a-z0-9_-]*$/.test(manifest.serviceUser || '')) throw new Error('a recall gateway needs a named broker host service_user')
  const socket = `[Unit]
Description=Hive read socket for nvoy instance ${id}

[Socket]
ListenStream=/run/nvoy-recall-gw/${id}/socket
Accept=yes
MaxConnections=4
SocketUser=${manifest.serviceUser}
SocketGroup=${group}
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
`
  const service = `[Unit]
Description=Hive read SSH gateway for nvoy instance ${id}
After=network-online.target
Wants=network-online.target

[Service]
User=${manifest.serviceUser}
Group=${group}
StandardInput=socket
StandardOutput=socket
StandardError=journal
SyslogIdentifier=${unit}
ExecStart=/usr/bin/ssh -F /dev/null -i /etc/nvoy/recall-keys/${id} -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/nvoy/recall-known-hosts -o ClearAllForwardings=yes -o ConnectTimeout=10 -o ConnectionAttempts=1 -T hive-memory-gw@herd-cloud
RuntimeMaxSec=25
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
`
  return { socketName: `${unit}.socket`, socket, serviceName: `${unit}@.service`, service, group }
}
