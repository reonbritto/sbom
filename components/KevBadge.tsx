import { Zap } from 'lucide-react';
import { Badge } from './ui/badge';

export function KevBadge({ dueDate }: { dueDate?: Date | string | null }) {
  const due = dueDate ? new Date(dueDate) : null;
  const overdue = due && due < new Date();
  return (
    <Badge
      variant="critical"
      title={due ? `CISA KEV — federal patch deadline: ${due.toLocaleDateString()}${overdue ? ' (OVERDUE)' : ''}` : 'CISA Known Exploited Vulnerabilities — actively exploited in the wild'}
    >
      <Zap size={11} fill="currentColor" />
      KEV
    </Badge>
  );
}
