import { SocSidebar } from "./Sidebar";
import { SocTopbar } from "./Topbar";

interface Props {
  title: string;
  sub?: string;
  children: React.ReactNode;
}

export function SocLayout({ title, sub, children }: Props) {
  return (
    <div className="h-screen w-full flex bg-background text-foreground overflow-hidden">
      <SocSidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <SocTopbar title={title} sub={sub} />
        <div className="flex-1 min-h-0 overflow-hidden">{children}</div>
      </div>
    </div>
  );
}
