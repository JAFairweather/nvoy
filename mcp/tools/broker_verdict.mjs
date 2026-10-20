// The verdict a broker child printed, cut down to what may reach the container log. A child's
// own verdict lines carry ids, an 8-hex sender prefix and a capability, never message content;
// anything else it printed (a nested tool's text output, a stack) is dropped rather than trusted
// to be equally clean. Bounded so one misbehaving child cannot flood the daemon's log.

const OWN = /^instance-broker(?:-native)?: /

export function childVerdict({ stdout = '', stderr = '' } = {}, { maxLines = 4, maxChars = 240 } = {}) {
  return `${stdout || ''}\n${stderr || ''}`.split('\n')
    .map(line => line.replace(/[\x00-\x1f\x7f]/g, '').trim())
    .filter(line => OWN.test(line))
    .slice(0, maxLines)
    .map(line => line.length > maxChars ? `${line.slice(0, maxChars - 1)}…` : line)
}
