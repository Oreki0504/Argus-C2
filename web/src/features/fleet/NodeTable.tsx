import { useFormat } from '../../lib/useFormat'
import { ArrowUpRight, Server } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { PublicNode } from '../../api/contracts'
import { EmptyState, ResourceMeter, Status } from '../../components/ui'
import { heartbeat } from '../../lib/format'

export function NodeTable({ nodes, now }: { nodes: PublicNode[]; now: number }) {
  const { relativeTime, timestampLabel } = useFormat()
  if (nodes.length === 0)
    return (
      <EmptyState title="No matching servers">Try a different name or heartbeat filter.</EmptyState>
    )
  return (
    <div className="table-scroll" role="region" aria-label="Fleet servers" tabIndex={0}>
      <table>
        <caption className="sr-only">
          Public fleet summaries. Resource measurements may be older than the latest heartbeat.
        </caption>
        <thead>
          <tr>
            <th scope="col">Server</th>
            <th scope="col">Heartbeat</th>
            <th scope="col">CPU</th>
            <th scope="col">Memory</th>
            <th scope="col">Disk</th>
            <th scope="col">Last seen</th>
            <th scope="col">
              <span className="sr-only">Details</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((node) => (
            <tr key={node.public_id}>
              <th scope="row">
                <Link className="server-link" to={`/fleet/${node.public_id}`}>
                  <span className="server-icon">
                    <Server size={17} strokeWidth={1.6} />
                  </span>
                  <span>
                    {node.display_name}
                    <small>
                      {node.system.os ?? 'System unavailable'} · {node.system.architecture ?? '—'}
                    </small>
                  </span>
                </Link>
              </th>
              <td>
                <Status>{heartbeat(node.last_seen_at, now)}</Status>
              </td>
              <td>
                <ResourceMeter
                  label={`${node.display_name} CPU`}
                  value={node.resources.cpu_percent}
                />
              </td>
              <td>
                <ResourceMeter
                  label={`${node.display_name} memory`}
                  value={node.resources.memory_percent}
                />
              </td>
              <td>
                <ResourceMeter
                  label={`${node.display_name} disk`}
                  value={node.resources.disk_percent}
                />
              </td>
              <td className="last-seen">
                <time
                  title={timestampLabel(node.last_seen_at)}
                  dateTime={
                    node.last_seen_at ? new Date(node.last_seen_at * 1000).toISOString() : undefined
                  }
                >
                  {relativeTime(node.last_seen_at, now)}
                </time>
                <small title={timestampLabel(node.resources.as_of)}>
                  Metrics {relativeTime(node.resources.as_of, now)}
                </small>
              </td>
              <td>
                <Link
                  className="table-detail-link"
                  to={`/fleet/${node.public_id}`}
                  aria-label={`View ${node.display_name}`}
                >
                  <ArrowUpRight size={17} />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
