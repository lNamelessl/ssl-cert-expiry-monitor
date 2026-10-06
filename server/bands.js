// Color-band mapping for days-remaining.
// >30 days green, 14-30 amber, <14 red. Anything without a usable cert
// reading (expired / invalid / unreachable / blocked) is red.
export function bandFor(daysRemaining, status) {
  if (status === 'expired' || status === 'invalid' || status === 'unreachable' || status === 'blocked') {
    return 'red';
  }
  if (daysRemaining === null || daysRemaining === undefined) return 'none';
  if (daysRemaining > 30) return 'green';
  if (daysRemaining >= 14) return 'amber';
  return 'red';
}
