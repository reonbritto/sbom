import { Sparkles } from 'lucide-react';
import { Badge } from './ui/badge';

export function DemoBadge() {
  return (
    <Badge variant="default" className="bg-primary/15 border-primary/40 text-primary border">
      <Sparkles size={10} />
      Demo
    </Badge>
  );
}
