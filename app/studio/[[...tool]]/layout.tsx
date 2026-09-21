// app/studio/[[...tool]]/layout.tsx
// Minimal layout for Sanity Studio — no sidebar

export const dynamic = 'force-dynamic';

export default function StudioLayout({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ height: '100vh' }}>
      {children}
    </div>
  );
}
