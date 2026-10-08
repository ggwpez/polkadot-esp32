export default {
  domain: 'example-door.dot',
  displayName: 'Door Keys',
  description: 'Select Alice, Bob, both, or neither, then Apply to update the RFID door.',
  icon: { path: './icon.png', format: 'png' },
  executables: [{ kind: 'app', path: './dist', appVersion: [1, 5, 3] }],
};
