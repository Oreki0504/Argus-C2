import { mkdtempSync, writeFileSync, existsSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { expect, test } from 'vitest'
import { installCommand } from './install-command'

// Exercise the pasted shell command with local download/sudo stand-ins. No
// network, privilege changes or system installation occurs in this test.
test.skipIf(process.platform === 'win32')(
  'curl/wget never execute incomplete downloads and remove temporary credentials',
  () => {
    for (const tool of ['curl', 'wget'] as const) {
      for (const status of [0, 1]) {
        const dir = mkdtempSync(join(tmpdir(), 'argus-command-test-'))
        try {
          writeFileSync(
            join(dir, tool),
            `#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in --output|-O) shift; target=$1;; esac
  shift
done
printf '%s' "$target" > "$ARGUS_TEST_DOWNLOAD"
cp "$ARGUS_TEST_SCRIPT" "$target"
exit "$ARGUS_TEST_DOWNLOAD_STATUS"
`,
            { mode: 0o700 },
          )
          writeFileSync(join(dir, 'sudo'), '#!/bin/sh\nexec "$@"\n', { mode: 0o700 })
          writeFileSync(join(dir, 'script'), '#!/bin/sh\nprintf executed > "$ARGUS_TEST_MARKER"\n')
          const marker = join(dir, 'executed')
          const download = join(dir, 'download-path')
          const result = spawnSync(
            'sh',
            ['-c', installCommand('https://example.invalid/v1/console/install/TEST', tool)],
            {
              env: {
                ...process.env,
                PATH: `${dir}:${process.env.PATH}`,
                ARGUS_TEST_SCRIPT: join(dir, 'script'),
                ARGUS_TEST_MARKER: marker,
                ARGUS_TEST_DOWNLOAD: download,
                ARGUS_TEST_DOWNLOAD_STATUS: String(status),
              },
              timeout: 5000,
            },
          )
          expect(result.error).toBeUndefined()
          expect(result.status).toBe(status)
          expect(existsSync(marker)).toBe(status === 0)
          expect(existsSync(readFileSync(download, 'utf8'))).toBe(false)
        } finally {
          rmSync(dir, { recursive: true, force: true })
        }
      }
    }
  },
)
