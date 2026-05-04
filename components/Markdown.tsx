import { renderMarkdown } from '@/lib/markdown';

export function Markdown({ source, className }: { source: string; className?: string }) {
  return (
    <div
      className={`md ${className ?? ''}`}
      dangerouslySetInnerHTML={{ __html: renderMarkdown(source) }}
    />
  );
}
